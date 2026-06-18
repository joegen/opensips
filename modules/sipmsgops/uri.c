/*
 * Various URI checks and Request URI manipulation
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#include <string.h>
#include "../../str.h"
#include "../../dprint.h"               /* Debugging */
#include "../../mem/mem.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_param.h"
#include "../../dset.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../data_lump.h"
#include "../../route.h"
#include "../../parser/contact/parse_contact.h"

#include "uri.h"

/*
 * Checks if From includes a To-tag -- good to identify
 * if a request creates a new dialog
 */
int has_totag(struct sip_msg* _m, char* _foo, char* _bar)
{
	str tag;

	if (!_m->to && parse_headers(_m, HDR_TO_F,0)==-1) {
		LM_ERR("To parsing failed\n");
		return -1;
	}
	if (!_m->to) {
		LM_ERR("no To\n");
		return -1;
	}
	tag=get_to(_m)->tag_value;
	if (tag.s==0 || tag.len==0) {
		LM_DBG("no totag\n");
		return -1;
	}
	LM_DBG("totag found\n");
	return 1;
}


/*
 * Find if Request URI has a given parameter with matching value
 */
int ruri_has_param(struct sip_msg* _msg, str* param, str* value)
{
	str t;
	param_hooks_t hooks;
	param_t *params, *p;

	if (parse_sip_msg_uri(_msg) < 0) {
	        LM_ERR("ruri parsing failed\n");
	        return -1;
	}

	t = _msg->parsed_uri.params;

	if (parse_params(&t, CLASS_ANY, &hooks, &params) < 0) {
	        LM_ERR("ruri parameter parsing failed\n");
	        return -1;
	}

	p = params;
	while (p) {
		if ((p->name.len == param->len) &&
		    (strncmp(p->name.s, param->s, param->len) == 0)) {
			if (value) {
				if ((value->len == p->body.len) &&
				    strncmp(value->s, p->body.s, value->len) == 0) {
					goto ok;
				} else {
					goto nok;
				}
			} else {
				if (p->body.len > 0) {
					goto nok;
				} else {
					goto ok;
				}
			}
		} else {
			p = p->next;
		}
	}

nok:
	free_params(params);
	return -1;

ok:
	free_params(params);
	return 1;
}



/*
 * Removes a given parameter from Request URI
 */
int ruri_del_param(struct sip_msg* _msg, str* _param)
{
	str param = *_param;
	str params;

	char  *tok_end;
	struct sip_uri *parsed_uri;

	str    param_tok, key;
	str    new_uri, old_uri;

	int begin_len, end_len;

	if (param.len == 0)
		return 1;

	if (parse_sip_msg_uri(_msg) < 0) {
		LM_ERR("ruri parsing failed\n");
		return -1;
	}

	parsed_uri = &(_msg->parsed_uri);

	params = parsed_uri->params;
	if (0 == params.s || 0 == params.len) {
		LM_DBG("RURI contains no params to delete! Returning...\n");
		return -1;
	}

	while (params.len) {
		tok_end = q_memchr(params.s, ';', params.len);

		param_tok.s = params.s;
		if (tok_end == NULL) {
			param_tok.len = params.len;
			params.len = 0;
		} else {
			param_tok.len = tok_end - params.s;
			params.len -= (param_tok.len + 1/*';' char*/);
			params.s   += (param_tok.len + 1);
		}

		tok_end = q_memchr(param_tok.s, '=', param_tok.len);
		if (tok_end == NULL) {
			key       = param_tok;
		} else {
			key.s     = param_tok.s;
			key.len   = tok_end - param_tok.s;
		}

		if (!str_strcmp(&param, &key)) {
			/* found the param to remove */
			/* include the leading ';' */
			param_tok.s--;
			param_tok.len++;
			old_uri = *GET_RURI(_msg);
			new_uri.len = old_uri.len - param_tok.len;
			new_uri.s = pkg_malloc(new_uri.len);
			if (!new_uri.s) {
				LM_ERR("no more pkg mem\n");
				return -1;
			}

			begin_len = param_tok.s - old_uri.s;
			memcpy(new_uri.s, old_uri.s, begin_len);

			end_len = old_uri.len - ((param_tok.s + param_tok.len) - old_uri.s);
			if (end_len)
				memcpy(new_uri.s + begin_len, param_tok.s + param_tok.len, end_len);

			if (set_ruri(_msg, &new_uri) < 0) {
				pkg_free(new_uri.s);
				LM_ERR("failed to set new R-URI\n");
				return -1;
			}

			pkg_free(new_uri.s);
			return 1;
		}
	}

	LM_DBG("requested key not found in RURI\n");

	return -1;
}

/*
 * Adds a new parameter to Request URI
 */
int ruri_add_param(struct sip_msg* _msg, str* _param)
{
	str param = *_param, *cur_uri, new_uri;
	struct sip_uri *parsed_uri;
	char *at;

	if (param.len == 0)
		return 1;

	if (parse_sip_msg_uri(_msg) < 0) {
	        LM_ERR("ruri parsing failed\n");
	        return -1;
	}

	parsed_uri = &(_msg->parsed_uri);

	/* if current ruri has no headers, pad param at the end */
	if (parsed_uri->headers.len == 0) {
		cur_uri =  GET_RURI(_msg);
		new_uri.len = cur_uri->len + param.len + 1;
		if (new_uri.len > MAX_URI_SIZE) {
			LM_ERR("new ruri too long\n");
			return -1;
		}
		new_uri.s = pkg_malloc(new_uri.len);
		if (new_uri.s == 0) {
			LM_ERR("Memory allocation failure\n");
			return -1;
		}
		memcpy(new_uri.s, cur_uri->s, cur_uri->len);
		*(new_uri.s + cur_uri->len) = ';';
		memcpy(new_uri.s + cur_uri->len + 1, param.s, param.len);
		if (set_ruri(_msg, &new_uri ) == 1) {
			goto ok;
		} else {
			goto nok;
		}
	}

	/* otherwise take the long path */
	new_uri.len = 4 +
		(parsed_uri->user.len ? parsed_uri->user.len + 1 : 0) +
		(parsed_uri->passwd.len ? parsed_uri->passwd.len + 1 : 0) +
		parsed_uri->host.len +
		(parsed_uri->port.len ? parsed_uri->port.len + 1 : 0) +
		parsed_uri->params.len + param.len + 1 +
		parsed_uri->headers.len + 1;
	if (new_uri.len > MAX_URI_SIZE) {
	        LM_ERR("new ruri too long\n");
		return -1;
	}

	new_uri.s = pkg_malloc(new_uri.len);
	if (new_uri.s == 0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	at = new_uri.s;
	memcpy(at, "sip:", 4);
	at = at + 4;
	if (parsed_uri->user.len) {
		memcpy(at, parsed_uri->user.s, parsed_uri->user.len);
		if (parsed_uri->passwd.len) {
			*at = ':';
			at = at + 1;
			memcpy(at, parsed_uri->passwd.s, parsed_uri->passwd.len);
			at = at + parsed_uri->passwd.len;
		};
		*at = '@';
		at = at + 1;
	}
	memcpy(at, parsed_uri->host.s, parsed_uri->host.len);
	at = at + parsed_uri->host.len;
	if (parsed_uri->port.len) {
		*at = ':';
		at = at + 1;
		memcpy(at, parsed_uri->port.s, parsed_uri->port.len);
		at = at + parsed_uri->port.len;
	}
	memcpy(at, parsed_uri->params.s, parsed_uri->params.len);
	at = at + parsed_uri->params.len;
	*at = ';';
	at = at + 1;
	memcpy(at, param.s, param.len);
	at = at + param.len;
	*at = '?';
	at = at + 1;
	memcpy(at, parsed_uri->headers.s, parsed_uri->headers.len);

	if (set_ruri(_msg, &new_uri) == 1) {
		goto ok;
	}

nok:
	pkg_free(new_uri.s);
	return -1;

ok:
	pkg_free(new_uri.s);
	return 1;
}


/*
 * Contact parameter editing (contact_*_param / contact_*_hdr_param).
 *
 * Tracker: coding_trackers tasks/opensips/ongoing/2026-06-18-1_contact-param-editing_P2.json
 * Architecture: architecture/opensips/contact_param_editing.json
 *
 * NOTE: task-1.0 build/compile gate — these are STUBS (return -1) so the
 * module registers and links cleanly before the per-phase logic lands.
 */

/* ---- Phase-1 shared helpers ---- */

/* DP-10: reject a name / unquoted value carrying RFC 3261 §19.1.1
 * non-paramchars (would yield an unparseable Contact). Returns 1 if unsafe. */
static int ct_token_bad(str* s)
{
	int i;

	if (!s || s->len == 0)
		return 1;
	for (i = 0; i < s->len; i++) {
		switch (s->s[i]) {
		case ';': case '>': case '?': case ',': case '\\':
		case ' ': case '\t': case '\r': case '\n':
			return 1;
		}
	}
	return 0;
}

/* DP-7/M-1: well-known URI params whose edit changes routing AND §19.1.4
 * URI-equality (binding match / de-registration). Warn (not block). */
static int ct_uri_param_wellknown(str* name)
{
	static const char* wk[] = {"transport", "ttl", "maddr", "method",
	                           "user", "lr", "gr", "ob", "comp", 0};
	int i;

	for (i = 0; wk[i]; i++)
		if (name->len == (int)strlen(wk[i]) &&
		    strncasecmp(name->s, wk[i], name->len) == 0)
			return 1;
	return 0;
}

/* warn once if 'name' (the part of param before '=') is a well-known URI param */
static void ct_warn_wellknown(str* param)
{
	str name = *param;
	char* eq = q_memchr(param->s, '=', param->len);

	if (eq)
		name.len = eq - param->s;
	if (ct_uri_param_wellknown(&name))
		LM_WARN("editing well-known URI param '%.*s' changes routing/identity "
		        "(RFC 3261 §19.1.4 binding match)\n", name.len, name.s);
}

/* C1/AD-3: select the index-th editable Contact (default 0 = top). Sets
 * *out and returns 0 on success; -1 on out-of-range / no editable contact
 * (a STAR contact yields none -> natural no-op). */
static int ct_select(struct sip_msg* _msg, int* _index, contact_t** _out)
{
	contact_t* c = NULL;
	int target = _index ? *_index : 0;
	int i = 0;

	if (target < 0)
		return -1;
	while (contact_iterator(&c, _msg, c) == 0 && c) {
		if (i == target) {
			*_out = c;
			return 0;
		}
		i++;
	}
	return -1;
}

/* DP-9: refuse a second edit of the same Contact. (1) the parsed bytes must
 * still point inside msg->buf (a prior whole-URI replacement moves them);
 * (2) no existing add_rm lump may fall within this Contact's byte span. */
static int ct_already_edited(struct sip_msg* _msg, contact_t* _c)
{
	static int warned_register = 0;
	struct lump* l;
	char* start = _c->name.s ? _c->name.s : _c->uri.s;
	unsigned int lo, hi;

	/* DP-5/R-22: advisory — these edits hit only the FORWARDED message and
	 * never reach the usrloc binding. Warn once on the likely misuse: a
	 * REGISTER in the main request route. (Not a hard block: editing a
	 * forwarded REGISTER relayed to an upstream registrar is legitimate.) */
	if (!warned_register && is_route_type(REQUEST_ROUTE) &&
	    _msg->first_line.type == SIP_REQUEST &&
	    _msg->REQ_METHOD == METHOD_REGISTER) {
		LM_WARN("contact_*_param edits the FORWARDED message only; it does "
		        "NOT modify the usrloc binding (forwarded-only)\n");
		warned_register = 1;
	}

	if (_c->uri.s < _msg->buf || _c->uri.s > _msg->buf + _msg->len ||
	    start < _msg->buf || start > _msg->buf + _msg->len)
		return 1;

	lo = (unsigned int)(start - _msg->buf);
	hi = (unsigned int)((start + _c->len) - _msg->buf);
	for (l = _msg->add_rm; l; l = l->next) {
		if ((l->op == LUMP_NOP || l->op == LUMP_DEL) &&
		    l->u.offset >= lo && l->u.offset <= hi)
			return 1;
	}
	return 0;
}

/* anchor a lump at offset and insert a pkg buffer after it (type 0 =
 * HDR_OTHER_T, matching add_rcv_param_f / replace_expires_ct_param). Takes
 * ownership of buf on success; frees it on failure. Returns 0 / -1. */
static int ct_lump_add(struct sip_msg* _msg, unsigned int offset, char* buf, int len)
{
	struct lump* anchor = anchor_lump(_msg, offset, 0);

	if (!anchor || !insert_new_lump_after(anchor, buf, len, 0)) {
		pkg_free(buf);
		return -1;
	}
	return 0;
}

/* Append ";<paramtext>" to a Contact URI's param region (DP-1: host:port
 * untouched). Enclosed form -> insert before '>'. Bare addr-spec -> wrap the
 * whole addr-spec in <...> first (AD-2/R-23 wrap-span: enclose c->uri only,
 * pre-existing header-params stay outside '>'). One coordinated edit. */
static int ct_uri_append_param(struct sip_msg* _msg, contact_t* _c,
                               struct sip_uri* _puri, str* _paramtext)
{
	char* q;
	char* buf;
	char* p;
	int len;
	int enclosed;
	unsigned int off;
	struct lump* del;

	/* enclosed iff the parser stripped a LAQUOT before c->uri (allow LWS) */
	q = _c->uri.s - 1;
	while (q > _msg->buf && (*q == ' ' || *q == '\t'))
		q--;
	enclosed = (q >= _msg->buf && *q == '<');

	if (enclosed) {
		off = _puri->params.len ?
		          (unsigned int)(_puri->params.s + _puri->params.len - _msg->buf) :
		      _puri->port.len ?
		          (unsigned int)(_puri->port.s + _puri->port.len - _msg->buf) :
		          (unsigned int)(_puri->host.s + _puri->host.len - _msg->buf);
		len = 1 + _paramtext->len;
		buf = pkg_malloc(len);
		if (!buf) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		p = buf;
		*p++ = ';';
		memcpy(p, _paramtext->s, _paramtext->len);
		return ct_lump_add(_msg, off, buf, len);
	}

	/* bare addr-spec: wrap in <...>, splicing the param into the URI's param
	 * region (BEFORE any '?'-headers), the '>' after the whole addr-spec.
	 * 'ins' is the offset within c->uri after host:port[;params]. */
	{
		int ins = _puri->params.len ?
		              (int)(_puri->params.s + _puri->params.len - _c->uri.s) :
		          _puri->port.len ?
		              (int)(_puri->port.s + _puri->port.len - _c->uri.s) :
		              (int)(_puri->host.s + _puri->host.len - _c->uri.s);

		off = (unsigned int)(_c->uri.s - _msg->buf);
		del = del_lump(_msg, off, _c->uri.len, 0);
		if (!del) {
			LM_ERR("del_lump failed\n");
			return -1;
		}
		len = 1 + _c->uri.len + 1 + _paramtext->len + 1;
		buf = pkg_malloc(len);
		if (!buf) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		p = buf;
		*p++ = '<';
		memcpy(p, _c->uri.s, ins);             /* user@host:port[;uri-params] */
		p += ins;
		*p++ = ';';
		memcpy(p, _paramtext->s, _paramtext->len);
		p += _paramtext->len;
		memcpy(p, _c->uri.s + ins, _c->uri.len - ins);  /* ?headers (if any) */
		p += _c->uri.len - ins;
		*p++ = '>';
		if (!insert_new_lump_after(del, buf, len, 0)) {
			pkg_free(buf);
			return -1;
		}
		return 0;
	}
}

/* ---- Family A — URI parameters (inside the Contact URI) ---- */

int contact_has_param(struct sip_msg* _msg, str* _name, str* _value, int* _index)
{
	contact_t* c;
	struct sip_uri puri;
	param_hooks_t hooks;
	param_t* params;
	param_t* p;
	str t;
	int ret = -1;

	if (!_name || _name->len == 0)
		return -1;
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (parse_uri(c->uri.s, c->uri.len, &puri) < 0) {
		LM_ERR("failed to parse contact uri\n");
		return -1;
	}
	t = puri.params;
	if (t.len == 0)
		return -1;
	if (parse_params(&t, CLASS_ANY, &hooks, &params) < 0)
		return -1;

	for (p = params; p; p = p->next) {
		if (p->name.len == _name->len &&
		    strncasecmp(p->name.s, _name->s, _name->len) == 0) {
			if (_value) {
				/* name case-insensitive (§19.1.4); value case-SENSITIVE
				 * (generic param values have no case rule — M-1) */
				ret = (_value->len == p->body.len &&
				       strncmp(p->body.s, _value->s, _value->len) == 0)
				          ? 1 : -1;
			} else {
				ret = 1; /* present regardless of value (OQ-10) */
			}
			break;
		}
	}
	free_params(params);
	return ret;
}

int contact_add_param(struct sip_msg* _msg, str* _param, int* _index)
{
	contact_t* c;
	struct sip_uri puri;

	if (ct_token_bad(_param))
		return -1;
	ct_warn_wellknown(_param);
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (ct_already_edited(_msg, c)) {
		LM_ERR("Contact already edited in this message\n");
		return -1;
	}
	if (parse_uri(c->uri.s, c->uri.len, &puri) < 0) {
		LM_ERR("failed to parse contact uri\n");
		return -1;
	}
	return ct_uri_append_param(_msg, c, &puri, _param) == 0 ? 1 : -1;
}

int contact_del_param(struct sip_msg* _msg, str* _name, int* _index)
{
	contact_t* c;
	struct sip_uri puri;
	str params, tok, key;
	char* semi;
	char* eq;

	if (!_name || _name->len == 0)
		return -1;
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (ct_already_edited(_msg, c)) {
		LM_ERR("Contact already edited in this message\n");
		return -1;
	}
	if (parse_uri(c->uri.s, c->uri.len, &puri) < 0) {
		LM_ERR("failed to parse contact uri\n");
		return -1;
	}
	params = puri.params;
	if (params.len == 0)
		return -1;

	while (params.len) {
		semi = q_memchr(params.s, ';', params.len);
		tok.s = params.s;
		if (!semi) {
			tok.len = params.len;
			params.len = 0;
		} else {
			tok.len = semi - params.s;
			params.len -= tok.len + 1;
			params.s += tok.len + 1;
		}
		eq = q_memchr(tok.s, '=', tok.len);
		key.s = tok.s;
		key.len = eq ? (eq - tok.s) : tok.len;
		if (key.len == _name->len &&
		    strncasecmp(key.s, _name->s, _name->len) == 0) {
			/* delete the token including its leading ';' */
			unsigned int off = (unsigned int)((tok.s - 1) - _msg->buf);
			if (!del_lump(_msg, off, tok.len + 1, 0))
				return -1;
			return 1;
		}
	}
	return -1; /* not found */
}

int contact_set_param(struct sip_msg* _msg, str* _name, str* _value, int* _index)
{
	contact_t* c;
	struct sip_uri puri;
	str params, tok, key, paramtext;
	char* semi;
	char* eq;
	char* buf;
	char* p;
	int found = 0;
	unsigned int off = 0;
	unsigned int dellen = 0;

	if (ct_token_bad(_name) || ct_token_bad(_value))
		return -1;
	ct_warn_wellknown(_name);
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (ct_already_edited(_msg, c)) {
		LM_ERR("Contact already edited in this message\n");
		return -1;
	}
	if (parse_uri(c->uri.s, c->uri.len, &puri) < 0) {
		LM_ERR("failed to parse contact uri\n");
		return -1;
	}

	/* locate an existing same-named param token */
	params = puri.params;
	while (params.len) {
		semi = q_memchr(params.s, ';', params.len);
		tok.s = params.s;
		if (!semi) {
			tok.len = params.len;
			params.len = 0;
		} else {
			tok.len = semi - params.s;
			params.len -= tok.len + 1;
			params.s += tok.len + 1;
		}
		eq = q_memchr(tok.s, '=', tok.len);
		key.s = tok.s;
		key.len = eq ? (eq - tok.s) : tok.len;
		if (key.len == _name->len &&
		    strncasecmp(key.s, _name->s, _name->len) == 0) {
			found = 1;
			off = (unsigned int)((tok.s - 1) - _msg->buf); /* incl leading ';' */
			dellen = tok.len + 1;
			break;
		}
	}

	/* build "name=value" */
	paramtext.len = _name->len + 1 + _value->len;
	if (!found) {
		char* tmp = pkg_malloc(paramtext.len);
		int rc;
		if (!tmp) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		p = tmp;
		memcpy(p, _name->s, _name->len);
		p += _name->len;
		*p++ = '=';
		memcpy(p, _value->s, _value->len);
		paramtext.s = tmp;
		rc = ct_uri_append_param(_msg, c, &puri, &paramtext);
		pkg_free(tmp);
		return rc == 0 ? 1 : -1;
	}

	/* replace: del old token (incl leading ';'), insert ";name=value" */
	{
		struct lump* del = del_lump(_msg, off, dellen, 0);
		if (!del)
			return -1;
		buf = pkg_malloc(1 + paramtext.len);
		if (!buf) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		p = buf;
		*p++ = ';';
		memcpy(p, _name->s, _name->len);
		p += _name->len;
		*p++ = '=';
		memcpy(p, _value->s, _value->len);
		if (!insert_new_lump_after(del, buf, 1 + paramtext.len, 0)) {
			pkg_free(buf);
			return -1;
		}
		return 1;
	}
}

/* ---- Family B helpers ---- */

/* DP-12: a value emitted as a quoted-string must not carry an unescaped
 * interior DQUOTE or any CR/LF (RFC 3261 §25.1 qdtext). Returns 1 if unsafe. */
/* A value emitted as a quoted-string must contain NO '"', '\', CR or LF.
 * OpenSIPS's parse_quoted_param is not quoted-pair-aware (it takes the first
 * '"' as the close), so we cannot safely escape an interior '"'/'\'; reject
 * them outright (H-1). CR/LF are not qdtext (RFC 3261 §25.1) either.
 * Consequence (documented v1 limit): a header-param value containing any of
 * these four chars is rejected. */
static int ct_qstring_bad(str* v)
{
	int i;

	for (i = 0; i < v->len; i++)
		switch (v->s[i]) {
		case '"': case '\\': case '\r': case '\n':
			return 1;
		}
	return 0;
}

/* DP-11/AD-4: header-param edit policy. -1 = REJECT (registrar-minted GRUU),
 * 1 = WARN (recognized standardized, semantics-bearing), 0 = silent (opaque).
 * Matched case-insensitively against the GENERIC param list (these are NOT
 * all parser hooks — pub-gruu/temp-gruu/reg-id live only in c->params). */
static int ct_hdr_policy(str* name)
{
	static const char* reject[] = {"pub-gruu", "temp-gruu", 0};
	static const char* warn[] = {"expires", "q", "+sip.instance", "reg-id",
	                             "methods", "received", 0};
	int i;

	for (i = 0; reject[i]; i++)
		if (name->len == (int)strlen(reject[i]) &&
		    strncasecmp(name->s, reject[i], name->len) == 0)
			return -1;
	for (i = 0; warn[i]; i++)
		if (name->len == (int)strlen(warn[i]) &&
		    strncasecmp(name->s, warn[i], name->len) == 0)
			return 1;
	return 0;
}

/* Locate header-field param 'name' (case-insensitive) in the generic list.
 * On success set *semi_off = offset of the leading ';' (LWS-absorbed) and
 * *span_len = bytes from that ';' through the param end (param_t.len already
 * includes '=' and any quotes). Returns 1 / 0. */
static int ct_hdr_find_span(struct sip_msg* _msg, contact_t* _c, str* _name,
                            unsigned int* _semi_off, unsigned int* _span_len)
{
	param_t* p;
	char* s;

	for (p = _c->params; p; p = p->next) {
		if (p->name.len == _name->len &&
		    strncasecmp(p->name.s, _name->s, _name->len) == 0) {
			s = p->name.s - 1;
			while (s > _msg->buf && (*s == ' ' || *s == '\t'))
				s--;
			if (*s != ';')           /* fallback: just before the name */
				s = p->name.s - 1;
			*_semi_off = (unsigned int)(s - _msg->buf);
			*_span_len = (unsigned int)((p->name.s + p->len) - s);
			return 1;
		}
	}
	return 0;
}

/* build ";name" / ";name=value" (value quoted iff quote) in pkg memory.
 * '"' / '\' / CR / LF are NOT escaped here — they are rejected upstream by
 * ct_qstring_bad, because OpenSIPS's parse_quoted_param (parse_param.c:171)
 * is NOT quoted-pair-aware (it takes the first '"' as the close), so a
 * backslash-escaped quote would terminate the quoted-string early (H-1). */
static char* ct_build_hdr_param(str* name, str* value, int quote, int* out_len)
{
	int len = 1 + name->len;
	char* buf;
	char* p;

	if (value)
		len += 1 + (quote ? 2 : 0) + value->len;
	buf = pkg_malloc(len);
	if (!buf) {
		LM_ERR("no more pkg memory\n");
		return 0;
	}
	p = buf;
	*p++ = ';';
	memcpy(p, name->s, name->len);
	p += name->len;
	if (value) {
		*p++ = '=';
		if (quote)
			*p++ = '"';
		memcpy(p, value->s, value->len);
		p += value->len;
		if (quote)
			*p++ = '"';
	}
	*out_len = len;
	return buf;
}

/* ---- Family B — Contact header-field parameters (after the '>') ---- */

int contact_has_hdr_param(struct sip_msg* _msg, str* _name, str* _value, int* _index)
{
	contact_t* c;
	param_t* p;

	if (!_name || _name->len == 0)
		return -1;
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	for (p = c->params; p; p = p->next) {
		if (p->name.len == _name->len &&
		    strncasecmp(p->name.s, _name->s, _name->len) == 0) {
			if (_value)
				/* name case-insensitive; value case-SENSITIVE (M-1) */
				return (_value->len == p->body.len &&
				        strncmp(p->body.s, _value->s, _value->len) == 0)
				           ? 1 : -1;
			return 1; /* present regardless of value (OQ-10) */
		}
	}
	return -1;
}

int contact_add_hdr_param(struct sip_msg* _msg, str* _param, int* _index)
{
	contact_t* c;
	str name;
	str value;
	str* vp = NULL;
	char* eq;
	char* buf;
	int len;
	int quote = 0;
	unsigned int off;

	if (!_param || _param->len == 0)
		return -1;

	/* split into name [= value]; value goes through value-driven quoting
	 * (DP-12) — NOT a raw append: an unquoted ',' would be re-parsed as a
	 * Contact-list separator (§20.10) and forge a second binding (review H-1). */
	eq = q_memchr(_param->s, '=', _param->len);
	name.s = _param->s;
	if (eq) {
		name.len = eq - _param->s;
		value.s = eq + 1;
		value.len = _param->len - name.len - 1;
		/* The value is taken as the LITERAL logical value: ct_build_hdr_param
		 * does all quoting AND quoted-pair escaping on emit (do NOT pass
		 * wire-form quotes — they become part of the value and get escaped). */
		if (value.len == 0)
			return -1; /* ';name=' is ill-formed (M-2) */
		vp = &value;
	} else {
		name.len = _param->len;
	}

	if (ct_token_bad(&name))
		return -1;
	switch (ct_hdr_policy(&name)) {
	case -1:
		LM_ERR("refusing to edit registrar-assigned param '%.*s'\n",
		       name.len, name.s);
		return -1;
	case 1:
		LM_WARN("editing semantics-bearing Contact param '%.*s'\n",
		        name.len, name.s);
		break;
	}
	if (vp) {
		quote = should_quote_contact_param_value(vp);
		if (quote && ct_qstring_bad(vp))
			return -1;
	}
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (ct_already_edited(_msg, c)) {
		LM_ERR("Contact already edited in this message\n");
		return -1;
	}
	off = (unsigned int)((c->name.s + c->len) - _msg->buf);
	buf = ct_build_hdr_param(&name, vp, quote, &len);
	if (!buf)
		return -1;
	return ct_lump_add(_msg, off, buf, len) == 0 ? 1 : -1;
}

int contact_del_hdr_param(struct sip_msg* _msg, str* _name, int* _index)
{
	contact_t* c;
	unsigned int semi_off;
	unsigned int span_len;

	if (!_name || _name->len == 0)
		return -1;
	switch (ct_hdr_policy(_name)) {
	case -1:
		LM_ERR("refusing to edit registrar-assigned param '%.*s'\n",
		       _name->len, _name->s);
		return -1;
	case 1:
		LM_WARN("editing semantics-bearing Contact param '%.*s'\n",
		        _name->len, _name->s);
		break;
	}
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (ct_already_edited(_msg, c)) {
		LM_ERR("Contact already edited in this message\n");
		return -1;
	}
	if (!ct_hdr_find_span(_msg, c, _name, &semi_off, &span_len))
		return -1; /* not found */
	if (!del_lump(_msg, semi_off, span_len, 0))
		return -1;
	return 1;
}

int contact_set_hdr_param(struct sip_msg* _msg, str* _name, str* _value, int* _index)
{
	contact_t* c;
	int quote;
	int len;
	char* buf;
	unsigned int semi_off;
	unsigned int span_len;

	if (!_name || _name->len == 0 || !_value || _value->len == 0)
		return -1; /* empty value -> ill-formed ';name=' (M-2) */
	if (ct_token_bad(_name))
		return -1;
	switch (ct_hdr_policy(_name)) {
	case -1:
		LM_ERR("refusing to edit registrar-assigned param '%.*s'\n",
		       _name->len, _name->s);
		return -1;
	case 1:
		LM_WARN("editing semantics-bearing Contact param '%.*s'\n",
		        _name->len, _name->s);
		break;
	}
	/* value-driven quoting (DP-12): quote iff the value carries non-token
	 * chars; a quoted value must pass the qdtext guard. */
	quote = should_quote_contact_param_value(_value);
	if (quote && ct_qstring_bad(_value))
		return -1;
	if (ct_select(_msg, _index, &c) < 0)
		return -1;
	if (ct_already_edited(_msg, c)) {
		LM_ERR("Contact already edited in this message\n");
		return -1;
	}
	buf = ct_build_hdr_param(_name, _value, quote, &len);
	if (!buf)
		return -1;

	if (ct_hdr_find_span(_msg, c, _name, &semi_off, &span_len)) {
		struct lump* del = del_lump(_msg, semi_off, span_len, 0);
		if (!del) {
			pkg_free(buf);
			return -1;
		}
		if (!insert_new_lump_after(del, buf, len, 0)) {
			pkg_free(buf);
			return -1;
		}
		return 1;
	}
	/* absent: append after the value-end (c->name.s + c->len) */
	return ct_lump_add(_msg, (unsigned int)((c->name.s + c->len) - _msg->buf),
	                   buf, len) == 0 ? 1 : -1;
}


/*
 * Converts Request-URI, if it is tel URI, to SIP URI.  Returns 1, if
 * conversion succeeded or if no conversion was needed, i.e., Request-URI
 * was not tel URI.  Returns -1, if conversion failed.
 */
int ruri_tel2sip(struct sip_msg* _msg)
{
	str *ruri;
	struct sip_uri *pfuri;
	str suri;
	char* at;

	ruri = GET_RURI(_msg);

	if (ruri->len < 4) return 1;

	if (strncasecmp(ruri->s, "tel:", 4) != 0){
		return 1;
	}

	if ((pfuri=parse_from_uri(_msg))==NULL) {
		LM_ERR("parsing From header failed\n");
		return -1;
	}

	suri.len = 4 + ruri->len - 4 + 1 + pfuri->host.len + 1 + 10;
	suri.s = pkg_malloc(suri.len);
	if (suri.s == 0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	at = suri.s;
	memcpy(at, "sip:", 4);
	at = at + 4;
	memcpy(at, ruri->s + 4, ruri->len - 4);
	at = at + ruri->len - 4;
	*at = '@';
	at = at + 1;
	memcpy(at, pfuri->host.s, pfuri->host.len);
	at = at + pfuri->host.len;
	*at = ';';
	at = at + 1;
	memcpy(at, "user=phone", 10);

	if (set_ruri(_msg, &suri) == 1) {
		pkg_free(suri.s);
		return 1;
	} else {
		pkg_free(suri.s);
		return -1;
	}
}


/*
 * Check if parameter is an e164 number.
 */
static inline int e164_check(str* _user)
{
    int i;
    char c;

    if ((_user->len > 2) && (_user->len < 17) && ((_user->s)[0] == '+')) {
	for (i = 1; i < _user->len; i++) {
	    c = (_user->s)[i];
	    if (c < '0' || c > '9') return -1;
	}
	return 1;
    }
    return -1;
}


/*
 * Check if user part of URI in pseudo variable is an e164 number
 */
int is_uri_user_e164(struct sip_msg* _m, str* uri)
{
	struct sip_uri puri;

	if (!uri->s || uri->len == 0) {
		LM_DBG("missing uri\n");
		return -1;
	}

	if (parse_uri(uri->s, uri->len, &puri) < 0) {
		LM_ERR("parsing URI failed\n");
		return -1;
	}

	return e164_check(&(puri.user));
}
