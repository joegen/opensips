/*
 * Unit tests for Contact parameter editing (contact_*_param / contact_*_hdr_param).
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <tap.h>
#include <string.h>

#include "../../../dprint.h"
#include "../../../str.h"
#include "../../../parser/msg_parser.h"
#include "../../../parser/contact/parse_contact.h"

#include "../uri.h"

#define CT_TEST_BUF 2048

/* Build + parse a REGISTER carrying the given raw Contact header value. */
static int mk_ct_req(const char *contact, struct sip_msg *msg)
{
	static char buf[CT_TEST_BUF];
	int len;

	len = snprintf(buf, CT_TEST_BUF,
		"REGISTER sip:registrar.example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK.ct.test\r\n"
		"From: <sip:alice@example.com>;tag=ctt\r\n"
		"To: <sip:alice@example.com>\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Call-ID: contact-param-test\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: %s\r\n"
		"Content-Length: 0\r\n"
		"\r\n", contact);

	memset(msg, 0, sizeof *msg);
	msg->buf = buf;
	msg->len = len;
	if (parse_msg(buf, len, msg) != 0)
		return -1;
	return 0;
}

/* Build + parse a REGISTER with TWO separate Contact header lines. */
static int mk_ct_req2(const char *c1, const char *c2, struct sip_msg *msg)
{
	static char buf[CT_TEST_BUF];
	int len;

	len = snprintf(buf, CT_TEST_BUF,
		"REGISTER sip:registrar.example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK.ct.t2\r\n"
		"From: <sip:alice@example.com>;tag=ctt\r\n"
		"To: <sip:alice@example.com>\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Call-ID: contact-param-test2\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: %s\r\n"
		"Contact: %s\r\n"
		"Content-Length: 0\r\n"
		"\r\n", c1, c2);

	memset(msg, 0, sizeof *msg);
	msg->buf = buf;
	msg->len = len;
	if (parse_msg(buf, len, msg) != 0)
		return -1;
	return 0;
}

/* Read-only family-A URI-param presence tests (no lumps involved). */
static void test_has_param(void)
{
	struct sip_msg msg;
	str transport = str_init("transport");
	str TRANSPORT = str_init("TRANSPORT");   /* case-insensitive (DP-8) */
	str xdm = str_init("x-dm");
	str tcp = str_init("tcp");
	str udp = str_init("udp");

	/* enclosed form with a URI param */
	if (ok(mk_ct_req("<sip:alice@1.2.3.4:5060;transport=tcp>", &msg) == 0,
	       "has: parse enclosed contact")) {
		ok(contact_has_param(&msg, &transport, NULL, NULL) == 1,
		   "has: transport present");
		ok(contact_has_param(&msg, &TRANSPORT, NULL, NULL) == 1,
		   "has: name match is case-insensitive");
		ok(contact_has_param(&msg, &transport, &tcp, NULL) == 1,
		   "has: transport=tcp value matches");
		ok(contact_has_param(&msg, &transport, &udp, NULL) == -1,
		   "has: transport=udp value mismatch -> not found");
		ok(contact_has_param(&msg, &xdm, NULL, NULL) == -1,
		   "has: absent param -> not found");
		free_sip_msg(&msg);
	}

	/* bare addr-spec: ';transport=tcp' is parsed as a HEADER param, NOT a URI
	 * param (enclosure-dependent boundary, DP-6) -> family A must NOT see it */
	if (ok(mk_ct_req("sip:alice@1.2.3.4:5060;transport=tcp", &msg) == 0,
	       "has: parse bare addr-spec")) {
		ok(contact_has_param(&msg, &transport, NULL, NULL) == -1,
		   "has(A): bare-addr-spec transport is a HEADER param, not URI (DP-6)");
		free_sip_msg(&msg);
	}
}

/* Read-only family-B header-param presence tests + namespace isolation. */
static void test_has_hdr_param(void)
{
	struct sip_msg msg;
	str q = str_init("q");
	str expires = str_init("expires");
	str transport = str_init("transport");
	str qval = str_init("0.5");

	if (ok(mk_ct_req("<sip:alice@1.2.3.4:5060;transport=tcp>;q=0.5;expires=3600",
	                 &msg) == 0, "has_hdr: parse contact w/ header params")) {
		ok(contact_has_hdr_param(&msg, &q, NULL, NULL) == 1,
		   "has_hdr: q present (header param)");
		ok(contact_has_hdr_param(&msg, &q, &qval, NULL) == 1,
		   "has_hdr: q=0.5 value matches");
		ok(contact_has_hdr_param(&msg, &expires, NULL, NULL) == 1,
		   "has_hdr: expires present");
		/* namespace isolation: transport is a URI param, NOT a header param */
		ok(contact_has_hdr_param(&msg, &transport, NULL, NULL) == -1,
		   "has_hdr(B): URI param 'transport' not seen by family B (DP-6)");
		/* and family A must not see the header param q */
		ok(contact_has_param(&msg, &q, NULL, NULL) == -1,
		   "has(A): header param 'q' not seen by family A (DP-6)");
		free_sip_msg(&msg);
	}
}

/* Apply msg->add_rm header lumps (NOP-anchor / DEL, each with a single
 * after-insert — exactly the shapes contact_*_param emit) onto msg->buf,
 * producing the forwarded bytes. add_rm is kept sorted by offset. */
static int render_lumps(struct sip_msg *msg, char *out, int outsz)
{
	struct lump *l, *a;
	int pos = 0, o = 0, i;

	for (l = msg->add_rm; l; l = l->next) {
		int off = (int)l->u.offset;
		for (i = pos; i < off && o < outsz - 1; i++)
			out[o++] = msg->buf[i];
		pos = off;
		for (a = l->before; a; a = a->before) {
			memcpy(out + o, a->u.value, a->len);
			o += a->len;
		}
		if (l->op == LUMP_DEL)
			pos += l->len;
		for (a = l->after; a; a = a->after) {
			memcpy(out + o, a->u.value, a->len);
			o += a->len;
		}
	}
	for (i = pos; i < msg->len && o < outsz - 1; i++)
		out[o++] = msg->buf[i];
	out[o] = '\0';
	return o;
}

/* assert the rendered forwarded message contains 'needle' */
static int rendered_has(struct sip_msg *msg, const char *needle)
{
	static char out[CT_TEST_BUF * 2];
	render_lumps(msg, out, sizeof(out));
	return strstr(out, needle) != NULL;
}

static void test_add_del_set_param(void)
{
	struct sip_msg msg;
	str xdm = str_init("x-dm");
	str v1 = str_init("alpha");
	str v2 = str_init("beta");
	str flag = str_init("ob");
	str transport = str_init("transport");

	/* add a URI param to an enclosed contact; host:port preserved */
	if (ok(mk_ct_req("<sip:alice@1.2.3.4:5060>", &msg) == 0, "A: parse")) {
		ok(contact_add_param(&msg, &(str){"x-dm=alpha", 10}, NULL) == 1, "A: add ok");
		ok(rendered_has(&msg, "<sip:alice@1.2.3.4:5060;x-dm=alpha>"),
		   "A: add -> ';x-dm=alpha' before '>', host:port intact");
		free_sip_msg(&msg);
	}

	/* add a flag (value-less) URI param */
	if (ok(mk_ct_req("<sip:alice@1.2.3.4:5060>", &msg) == 0, "A: parse flag")) {
		ok(contact_add_param(&msg, &flag, NULL) == 1, "A: add flag ok");
		ok(rendered_has(&msg, "<sip:alice@1.2.3.4:5060;ob>"), "A: flag param added");
		free_sip_msg(&msg);
	}

	/* del a URI param (middle/last) */
	if (ok(mk_ct_req("<sip:a@h:5060;x-dm=alpha;lr>", &msg) == 0, "A: parse for del")) {
		ok(contact_del_param(&msg, &xdm, NULL) == 1, "A: del ok");
		ok(rendered_has(&msg, "<sip:a@h:5060;lr>"), "A: x-dm removed, lr kept");
		ok(!rendered_has(&msg, "x-dm"), "A: x-dm fully gone");
		free_sip_msg(&msg);
	}

	/* set existing -> replace value */
	if (ok(mk_ct_req("<sip:a@h;x-dm=alpha>", &msg) == 0, "A: parse for set-replace")) {
		ok(contact_set_param(&msg, &xdm, &v2, NULL) == 1, "A: set replace ok");
		ok(rendered_has(&msg, "x-dm=beta") && !rendered_has(&msg, "alpha"),
		   "A: value replaced alpha->beta");
		free_sip_msg(&msg);
	}

	/* set absent -> add */
	if (ok(mk_ct_req("<sip:a@h:5060>", &msg) == 0, "A: parse for set-add")) {
		ok(contact_set_param(&msg, &xdm, &v1, NULL) == 1, "A: set add ok");
		ok(rendered_has(&msg, "<sip:a@h:5060;x-dm=alpha>"), "A: set added param");
		free_sip_msg(&msg);
	}

	/* AUTO-WRAP: bare addr-spec add wraps in <...> (AD-2/R-23) */
	if (ok(mk_ct_req("sip:alice@1.2.3.4:5060", &msg) == 0, "A: parse bare")) {
		ok(contact_add_param(&msg, &(str){"x-dm=alpha", 10}, NULL) == 1,
		   "A: add to bare ok");
		ok(rendered_has(&msg, "<sip:alice@1.2.3.4:5060;x-dm=alpha>"),
		   "A: bare addr-spec auto-wrapped in <...>");
		free_sip_msg(&msg);
	}

	/* DP-10: dangerous value rejected */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "A: parse for dp10")) {
		ok(contact_add_param(&msg, &(str){"x=a;b", 5}, NULL) == -1,
		   "A: value with ';' rejected (DP-10)");
		free_sip_msg(&msg);
	}

	/* family A must not touch / find header params already validated above */
	(void)transport;
}

static void test_hdr_param(void)
{
	struct sip_msg msg;
	str expires = str_init("expires");
	str e2 = str_init("60");
	str pubgruu = str_init("pub-gruu");
	str gv = str_init("sip:x@y");
	str inst = str_init("+sip.instance");
	str urn = str_init("<urn:uuid:abc>");

	/* add an opaque header param after '>' (URI untouched) */
	if (ok(mk_ct_req("<sip:a@1.2.3.4:5060;transport=tcp>;q=0.5", &msg) == 0,
	       "B: parse")) {
		ok(contact_add_hdr_param(&msg, &(str){"x-tag=v", 7}, NULL) == 1,
		   "B: add_hdr ok");
		ok(rendered_has(&msg, ";x-tag=v"), "B: header param appended");
		ok(rendered_has(&msg, "sip:a@1.2.3.4:5060;transport=tcp"),
		   "B: URI (incl its transport param) untouched");
		free_sip_msg(&msg);
	}

	/* set expires (warn-but-allowed) -> replace */
	if (ok(mk_ct_req("<sip:a@h>;expires=3600", &msg) == 0, "B: parse expires")) {
		ok(contact_set_hdr_param(&msg, &expires, &e2, NULL) == 1, "B: set expires ok");
		ok(rendered_has(&msg, "expires=60") && !rendered_has(&msg, "3600"),
		   "B: expires replaced 3600->60");
		free_sip_msg(&msg);
	}

	/* REJECT pub-gruu/temp-gruu (registrar-minted, DP-11) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "B: parse for reject")) {
		ok(contact_set_hdr_param(&msg, &pubgruu, &gv, NULL) == -1,
		   "B: pub-gruu edit rejected (DP-11)");
		ok(contact_add_hdr_param(&msg, &(str){"temp-gruu=sip:z@y", 17}, NULL) == -1,
		   "B: temp-gruu add rejected (DP-11)");
		free_sip_msg(&msg);
	}

	/* DP-12 value-driven quoting: +sip.instance value needs quotes */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "B: parse for quote")) {
		ok(contact_set_hdr_param(&msg, &inst, &urn, NULL) == 1, "B: set +sip.instance ok");
		ok(rendered_has(&msg, "+sip.instance=\"<urn:uuid:abc>\""),
		   "B: value DQUOTE-wrapped (DP-12)");
		free_sip_msg(&msg);
	}
}

static void test_index_star(void)
{
	struct sip_msg msg;
	str xdm = str_init("x-dm");
	str v = str_init("v");
	int i0 = 0, i1 = 1, i9 = 9;

	/* two comma-separated contacts with distinct q-values */
	if (ok(mk_ct_req("<sip:a@1.1.1.1>;q=0.7, <sip:b@2.2.2.2>;q=0.4", &msg) == 0,
	       "IDX: parse 2 contacts")) {
		/* default (NULL) edits the top contact */
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, NULL) == 1,
		   "IDX: add default -> top");
		ok(rendered_has(&msg, "<sip:a@1.1.1.1;x-dm=v>"), "IDX: top contact edited");
		ok(rendered_has(&msg, "<sip:b@2.2.2.2>;q=0.4"),
		   "IDX: 2nd contact + its q untouched (q-ordering preserved)");
		free_sip_msg(&msg);
	}

	/* explicit index 1 targets the second contact */
	if (ok(mk_ct_req("<sip:a@1.1.1.1>;q=0.7, <sip:b@2.2.2.2>;q=0.4", &msg) == 0,
	       "IDX: parse for index 1")) {
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, &i1) == 1, "IDX: add index 1");
		ok(rendered_has(&msg, "<sip:b@2.2.2.2;x-dm=v>"), "IDX: 2nd contact edited");
		ok(rendered_has(&msg, "<sip:a@1.1.1.1>;q=0.7"), "IDX: 1st contact untouched");
		free_sip_msg(&msg);
	}

	/* out-of-range index -> -1 */
	if (ok(mk_ct_req("<sip:a@1.1.1.1>", &msg) == 0, "IDX: parse for oob")) {
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, &i9) == -1,
		   "IDX: out-of-range index -> -1");
		ok(contact_has_param(&msg, &xdm, NULL, &i0) == -1, "IDX: has index 0 absent");
		free_sip_msg(&msg);
	}

	/* STAR contact yields no editable contact (natural no-op) */
	if (ok(mk_ct_req("*", &msg) == 0, "IDX: parse STAR")) {
		ok(contact_add_param(&msg, &xdm, NULL) == -1, "IDX: add on STAR -> -1 (no-op)");
		ok(contact_has_param(&msg, &xdm, NULL, NULL) == -1, "IDX: has on STAR -> -1");
		free_sip_msg(&msg);
	}
	(void)v;
}

static void test_single_edit_guard(void)
{
	struct sip_msg msg;

	/* a second edit of the same Contact in one message is refused (DP-9/R-8) */
	if (ok(mk_ct_req("<sip:a@1.2.3.4:5060>", &msg) == 0, "GUARD: parse")) {
		ok(contact_add_param(&msg, &(str){"x-dm=1", 6}, NULL) == 1, "GUARD: 1st edit ok");
		ok(contact_add_param(&msg, &(str){"y=2", 3}, NULL) == -1,
		   "GUARD: 2nd edit on same Contact -> -1 (DP-9)");
		free_sip_msg(&msg);
	}
}

static void test_edge(void)
{
	struct sip_msg msg;
	str pubgruu = str_init("pub-gruu");
	str tempgruu = str_init("temp-gruu");
	str regid = str_init("reg-id");
	str inst = str_init("+sip.instance");
	str expires = str_init("expires");
	str e60 = str_init("60");
	str methods = str_init("methods");
	str mval = str_init("INVITE,BYE");
	str badq = {"a\"b", 3};
	str badcrlf = {"a\r\nb", 4};
	str xn = str_init("x");

	/* 5.4: auto-wrap of a bare addr-spec that already carries a HEADER param
	 * (;q): q must remain OUTSIDE the new '>' */
	if (ok(mk_ct_req("sip:a@1.2.3.4:5060;q=0.5", &msg) == 0, "EDGE: parse bare+q")) {
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, NULL) == 1, "EDGE: add ok");
		ok(rendered_has(&msg, "<sip:a@1.2.3.4:5060;x-dm=v>;q=0.5"),
		   "EDGE: bare+hdr-param wrap -> ;q stays outside '>'");
		free_sip_msg(&msg);
	}

	/* 5.4: auto-wrap with '?'-URI-headers: param goes BEFORE '?', '>' after */
	if (ok(mk_ct_req("sip:a@b?Subject=x", &msg) == 0, "EDGE: parse bare+?hdrs")) {
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, NULL) == 1, "EDGE: add ok2");
		ok(rendered_has(&msg, "<sip:a@b;x-dm=v?Subject=x>"),
		   "EDGE: param spliced before '?'-URI-headers");
		free_sip_msg(&msg);
	}

	/* 5.10: sips: bare addr-spec auto-wrap preserves the scheme */
	if (ok(mk_ct_req("sips:a@1.2.3.4:5061", &msg) == 0, "EDGE: parse sips")) {
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, NULL) == 1, "EDGE: sips add ok");
		ok(rendered_has(&msg, "<sips:a@1.2.3.4:5061;x-dm=v>"),
		   "EDGE: sips scheme preserved through auto-wrap");
		free_sip_msg(&msg);
	}

	/* 5.5: full RFC5627/5626 Contact — gruu/reg-id matched from the GENERIC
	 * params list (not parser hooks); per-param disposition */
	if (ok(mk_ct_req("<sip:a@h>;+sip.instance=\"<urn:uuid:x>\";reg-id=1;"
	                 "pub-gruu=\"sip:p@h\";temp-gruu=\"sip:t@h\";q=0.5;expires=3600",
	                 &msg) == 0, "EDGE: parse RFC5627 contact")) {
		ok(contact_has_hdr_param(&msg, &regid, NULL, NULL) == 1,
		   "EDGE: reg-id found via generic list (not a hook)");
		ok(contact_has_hdr_param(&msg, &inst, NULL, NULL) == 1,
		   "EDGE: +sip.instance found");
		ok(contact_set_hdr_param(&msg, &pubgruu, &(str){"sip:z@h", 7}, NULL) == -1,
		   "EDGE: pub-gruu edit rejected (from generic list)");
		ok(contact_del_hdr_param(&msg, &tempgruu, NULL) == -1,
		   "EDGE: temp-gruu del rejected");
		ok(contact_set_hdr_param(&msg, &expires, &e60, NULL) == 1,
		   "EDGE: expires warn+replace ok");
		free_sip_msg(&msg);
	}

	/* 5.6: injection torture — interior DQUOTE / CR-LF rejected (DP-12) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "EDGE: parse for injection")) {
		ok(contact_set_hdr_param(&msg, &xn, &badq, NULL) == -1,
		   "EDGE: value with raw '\"' rejected (DP-12 qdtext)");
		ok(contact_set_hdr_param(&msg, &xn, &badcrlf, NULL) == -1,
		   "EDGE: value with CR/LF rejected (DP-12)");
		free_sip_msg(&msg);
	}

	/* 5.6: a legal value with ',' is settable via the quoted path (M-1 fix) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "EDGE: parse for methods")) {
		ok(contact_set_hdr_param(&msg, &methods, &mval, NULL) == 1,
		   "EDGE: methods='INVITE,BYE' settable (warn) via quoted path");
		ok(rendered_has(&msg, "methods=\"INVITE,BYE\""),
		   "EDGE: comma value DQUOTE-wrapped (not rejected by DP-10)");
		free_sip_msg(&msg);
	}
}

/* Coverage for the steps-4-8 review fixes (H-1, M-1, M-2, M-3). */
static void test_review_fixes(void)
{
	struct sip_msg msg;
	str x = str_init("x");
	str empty = {"", 0};
	int i1 = 1;

	/* H-1: a ',' in an add_hdr_param value is now QUOTED, not raw-appended,
	 * so it cannot forge a second Contact (§20.10) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF: parse for inject")) {
		ok(contact_add_hdr_param(&msg, &(str){"x=a,sip:evil@h", 14}, NULL) == 1,
		   "RF: add_hdr with ',' value ok");
		ok(rendered_has(&msg, ";x=\"a,sip:evil@h\""),
		   "RF: comma value DQUOTE-wrapped -> no contact injection (H-1)");
		free_sip_msg(&msg);
	}

	/* M-2: empty value rejected (both families) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF: parse for empty")) {
		ok(contact_add_hdr_param(&msg, &(str){"x=", 2}, NULL) == -1,
		   "RF: add_hdr 'x=' (empty value) -> -1 (M-2)");
		ok(contact_set_hdr_param(&msg, &x, &empty, NULL) == -1,
		   "RF: set_hdr empty value -> -1 (M-2)");
		free_sip_msg(&msg);
	}

	/* M-1: well-known URI param edit still applies (a one-time LM_WARN is
	 * logged; the edit is allowed, not blocked) */
	if (ok(mk_ct_req("<sip:a@h:5060>", &msg) == 0, "RF: parse for well-known")) {
		ok(contact_add_param(&msg, &(str){"transport=tcp", 13}, NULL) == 1,
		   "RF: well-known 'transport' applied (warns, M-1)");
		ok(rendered_has(&msg, "<sip:a@h:5060;transport=tcp>"), "RF: transport added");
		free_sip_msg(&msg);
	}

	/* M-3: two SEPARATE Contact headers; index 1 targets the second */
	if (ok(mk_ct_req2("<sip:a@1.1.1.1>", "<sip:b@2.2.2.2>", &msg) == 0,
	       "RF: parse 2 separate Contact headers")) {
		ok(contact_add_param(&msg, &(str){"x-dm=v", 6}, &i1) == 1,
		   "RF: edit 2nd of two separate Contact headers");
		ok(rendered_has(&msg, "<sip:b@2.2.2.2;x-dm=v>"), "RF: 2nd header edited");
		ok(rendered_has(&msg, "<sip:a@1.1.1.1>"), "RF: 1st header untouched");
		free_sip_msg(&msg);
	}
}

/* Round-2 review fixes: M-A (wire-form quoted add), M-B (guard coverage),
 * L-4 (existing-quoted-param span), trailing-backslash. */
static void test_review_fixes2(void)
{
	struct sip_msg msg;
	str methods = str_init("methods");
	str byeack = str_init("BYE,ACK");
	str x = str_init("x");
	str xq = str_init("x-q");
	str xdm = str_init("x-dm");
	str trailbs = {"a\\", 2};

	/* M-A: the value is the LITERAL logical value; the function quotes + escapes.
	 * Pass the unquoted instance value -> exactly one quoted pair on the wire. */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF2: parse for quoted-add")) {
		ok(contact_add_hdr_param(&msg,
		     &(str){"+sip.instance=<urn:uuid:z>", 26}, NULL) == 1,
		   "RF2: add_hdr unquoted value accepted (literal model, M-A)");
		ok(rendered_has(&msg, "+sip.instance=\"<urn:uuid:z>\""),
		   "RF2: emitted as exactly one quoted pair");
		free_sip_msg(&msg);
	}

	/* M-1: has value comparison is case-SENSITIVE (names stay insensitive) */
	if (ok(mk_ct_req("<sip:a@h:5060;x-dm=alpha>", &msg) == 0, "RF2: parse for M-1")) {
		str xdm2 = str_init("x-dm");
		str ALPHA = str_init("ALPHA");
		str alpha = str_init("alpha");
		ok(contact_has_param(&msg, &xdm2, &alpha, NULL) == 1,
		   "RF2: value 'alpha' matches");
		ok(contact_has_param(&msg, &xdm2, &ALPHA, NULL) == -1,
		   "RF2: value 'ALPHA' does NOT match (case-sensitive value, M-1)");
		free_sip_msg(&msg);
	}

	/* H-1: a value containing '"' or '\' cannot be safely emitted as an
	 * OpenSIPS quoted-string (parse_quoted_param is not quoted-pair-aware), so
	 * it is REJECTED — the ';evil=1' injection payload never reaches the wire.
	 * (The even-backslash-run lookbehind bypass is closed by rejecting outright.) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF2: parse for H-1")) {
		ok(contact_set_hdr_param(&msg, &x, &(str){"a\\\\\"x;evil=1", 12}, NULL) == -1,
		   "RF2: hostile value with '\\'+'\"' rejected (H-1, no injection)");
		ok(contact_set_hdr_param(&msg, &x, &(str){"a\"b", 3}, NULL) == -1,
		   "RF2: interior '\"' rejected (H-1)");
		ok(contact_set_hdr_param(&msg, &x, &(str){"a\\b", 3}, NULL) == -1,
		   "RF2: interior '\\' rejected (H-1, no value corruption)");
		free_sip_msg(&msg);
	}

	/* literal-value model: a wire-form value carrying literal quotes is
	 * rejected (interior '"'), not silently stripped (round-4) */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF2: parse for literal-quote")) {
		ok(contact_add_hdr_param(&msg, &(str){"x=\"y\"", 5}, NULL) == -1,
		   "RF2: wire-form 'x=\"y\"' rejected (literal-value model)");
		free_sip_msg(&msg);
	}

	/* M-B: second edit after a DEL on the same Contact -> -1 */
	if (ok(mk_ct_req("<sip:a@h;x-dm=1;lr>", &msg) == 0, "RF2: parse del-then")) {
		ok(contact_del_param(&msg, &xdm, NULL) == 1, "RF2: del ok");
		ok(contact_add_param(&msg, &(str){"y=2", 3}, NULL) == -1,
		   "RF2: edit after del -> -1 (DP-9)");
		free_sip_msg(&msg);
	}

	/* M-B: second edit after the bare-addr-spec AUTO-WRAP -> -1 */
	if (ok(mk_ct_req("sip:a@1.2.3.4:5060", &msg) == 0, "RF2: parse wrap-then")) {
		ok(contact_add_param(&msg, &(str){"x-dm=1", 6}, NULL) == 1, "RF2: wrap-add ok");
		ok(contact_add_param(&msg, &(str){"y=2", 3}, NULL) == -1,
		   "RF2: edit after auto-wrap -> -1 (DP-9)");
		free_sip_msg(&msg);
	}

	/* M-B: family-B second edit on the same Contact -> -1 */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF2: parse B-double")) {
		ok(contact_add_hdr_param(&msg, &(str){"x=1", 3}, NULL) == 1, "RF2: B add ok");
		ok(contact_add_hdr_param(&msg, &(str){"z=2", 3}, NULL) == -1,
		   "RF2: family-B 2nd edit -> -1 (DP-9)");
		free_sip_msg(&msg);
	}

	/* L-4: replace an EXISTING quoted header param -> del span absorbs the
	 * surrounding DQUOTEs (R-24), no orphan quote left */
	if (ok(mk_ct_req("<sip:a@h>;methods=\"INVITE\"", &msg) == 0,
	       "RF2: parse existing-quoted")) {
		ok(contact_set_hdr_param(&msg, &methods, &byeack, NULL) == 1,
		   "RF2: set existing quoted param ok");
		ok(rendered_has(&msg, "methods=\"BYE,ACK\"") && !rendered_has(&msg, "INVITE"),
		   "RF2: quoted value replaced cleanly (R-24)");
		free_sip_msg(&msg);
	}

	/* L-4: delete an EXISTING quoted param -> no orphan DQUOTE */
	if (ok(mk_ct_req("<sip:a@h>;x-q=\"a,b\";lr", &msg) == 0,
	       "RF2: parse del-quoted")) {
		ok(contact_del_hdr_param(&msg, &xq, NULL) == 1, "RF2: del quoted ok");
		ok(!rendered_has(&msg, "x-q") && !rendered_has(&msg, "\"a,b\"") &&
		   rendered_has(&msg, ";lr"),
		   "RF2: quoted param fully removed, lr kept, no orphan quote");
		free_sip_msg(&msg);
	}

	/* L-2: trailing unescaped backslash rejected (would escape closing ") */
	if (ok(mk_ct_req("<sip:a@h>", &msg) == 0, "RF2: parse trail-bs")) {
		ok(contact_set_hdr_param(&msg, &x, &trailbs, NULL) == -1,
		   "RF2: trailing-backslash value -> -1 (L-2)");
		free_sip_msg(&msg);
	}
}

void mod_tests(void)
{
	test_has_param();
	test_has_hdr_param();
	test_add_del_set_param();
	test_hdr_param();
	test_index_star();
	test_single_edit_guard();
	test_edge();
	test_review_fixes();
	test_review_fixes2();
}
