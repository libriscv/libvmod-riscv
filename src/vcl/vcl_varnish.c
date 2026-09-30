#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <cache/cache.h>
#include <vcl.h>
#include <vre.h>
#include <vrt_obj.h>
#include <vsa.h>
#include <vsb.h>

#include "vcl_varnish.h"

/* Longest header name we build a Varnish header spec for. The spec's
   length prefix is one byte, and the policy ABI caps names at 1024 before
   they get here, so anything longer than the prefix can say is refused. */
#define VCLV_MAX_SPEC_NAME 254

enum vcl_phase
vclv_phase(VRT_CTX)
{
	switch (ctx->method) {
	case VCL_MET_RECV:             return (VCL_PHASE_RECV);
	case VCL_MET_BACKEND_FETCH:    return (VCL_PHASE_BACKEND_FETCH);
	case VCL_MET_BACKEND_RESPONSE: return (VCL_PHASE_BACKEND_RESPONSE);
	case VCL_MET_DELIVER:          return (VCL_PHASE_DELIVER);
	case VCL_MET_SYNTH:            return (VCL_PHASE_SYNTH);
	default:                       return (VCL_PHASE_NONE);
	}
}

struct http *
vclv_http(VRT_CTX, enum vcl_side side)
{
	switch (vclv_phase(ctx)) {
	case VCL_PHASE_RECV:
		return (side == VCL_SIDE_REQUEST ? ctx->http_req : NULL);
	case VCL_PHASE_DELIVER:
	case VCL_PHASE_SYNTH:
		return (side == VCL_SIDE_REQUEST ? ctx->http_req : ctx->http_resp);
	case VCL_PHASE_BACKEND_FETCH:
		return (side == VCL_SIDE_REQUEST ? ctx->http_bereq : NULL);
	case VCL_PHASE_BACKEND_RESPONSE:
		return (side == VCL_SIDE_REQUEST ? ctx->http_bereq : ctx->http_beresp);
	case VCL_PHASE_NONE:
		break;
	}
	return (NULL);
}

/* Varnish names a header as a length-prefixed "Name:" string. */
static int
header_spec(char *spec, const char *name, size_t nlen)
{
	if (nlen == 0 || nlen > VCLV_MAX_SPEC_NAME)
		return (-1);
	spec[0] = (char)(nlen + 1);
	memcpy(spec + 1, name, nlen);
	spec[nlen + 1] = ':';
	spec[nlen + 2] = '\0';
	return (0);
}

int
vclv_get(const struct http *hp, const char *name, size_t nlen,
    const char **value, size_t *vlen)
{
	char spec[VCLV_MAX_SPEC_NAME + 3];
	const char *v;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (header_spec(spec, name, nlen) < 0)
		return (-1);
	if (!http_GetHdr(hp, spec, &v))
		return (-1);
	*value = v;
	*vlen = strlen(v);
	return (0);
}

int
vclv_add(VRT_CTX, struct http *hp, const char *name, size_t nlen,
    const char *value, size_t vlen)
{
	const char *field;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (nlen == 0 || nlen > INT_MAX || vlen > INT_MAX)
		return (-1);
	if (hp->nhd >= hp->shd) {
		VSLb(ctx->vsl, SLT_LostHeader, "%.*s", (int)nlen, name);
		return (-1);
	}
	field = WS_Printf(hp->ws, "%.*s: %.*s",
	    (int)nlen, name, (int)vlen, value);
	if (field == NULL) {
		VSLb(ctx->vsl, SLT_LostHeader, "%.*s", (int)nlen, name);
		return (-1);
	}
	http_SetHeader(hp, field);
	return (0);
}

int
vclv_set(VRT_CTX, struct http *hp, const char *name, size_t nlen,
    const char *value, size_t vlen)
{
	vclv_unset(hp, name, nlen);
	return (vclv_add(ctx, hp, name, nlen, value, vlen));
}

void
vclv_unset(struct http *hp, const char *name, size_t nlen)
{
	char spec[VCLV_MAX_SPEC_NAME + 3];

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (header_spec(spec, name, nlen) < 0)
		return;
	http_Unset(hp, spec);
}

int
vclv_next(const struct http *hp, unsigned *cursor,
    const char **name, size_t *nlen, const char **value, size_t *vlen)
{
	unsigned u;
	const char *b, *e, *colon;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	for (u = *cursor + HTTP_HDR_FIRST; u < hp->nhd; u++) {
		b = hp->hd[u].b;
		e = hp->hd[u].e;
		if (b == NULL)
			continue;
		colon = memchr(b, ':', e - b);
		if (colon == NULL)
			continue;
		*name = b;
		*nlen = colon - b;
		colon++;
		while (colon < e && (*colon == ' ' || *colon == '\t'))
			colon++;
		*value = colon;
		*vlen = e - colon;
		*cursor = u + 1 - HTTP_HDR_FIRST;
		return (0);
	}
	*cursor = u - HTTP_HDR_FIRST;
	return (-1);
}

const char *
vclv_url(const struct http *hp, size_t *len)
{
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	*len = Tlen(hp->hd[HTTP_HDR_URL]);
	return (hp->hd[HTTP_HDR_URL].b);
}

const char *
vclv_method(const struct http *hp, size_t *len)
{
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	*len = Tlen(hp->hd[HTTP_HDR_METHOD]);
	return (hp->hd[HTTP_HDR_METHOD].b);
}

int
vclv_set_url(VRT_CTX, struct http *hp, const char *url, size_t len)
{
	char *copy;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (len > INT_MAX)
		return (-1);
	copy = WS_Copy(hp->ws, url, (int)len + 1);
	if (copy == NULL) {
		VSLb(ctx->vsl, SLT_VCL_Error, "vcl: out of workspace setting the URL");
		return (-1);
	}
	copy[len] = '\0';
	http_SetH(hp, HTTP_HDR_URL, copy);
	return (0);
}

unsigned
vclv_status(const struct http *hp)
{
	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	return (hp->status);
}

double
vclv_get_duration(VRT_CTX, enum vcl_duration which)
{
	switch (which) {
	case VCL_TTL:   return (VRT_r_beresp_ttl(ctx));
	case VCL_GRACE: return (VRT_r_beresp_grace(ctx));
	case VCL_KEEP:  return (VRT_r_beresp_keep(ctx));
	}
	return (0);
}

void
vclv_set_duration(VRT_CTX, enum vcl_duration which, double seconds)
{
	switch (which) {
	case VCL_TTL:   VRT_l_beresp_ttl(ctx, seconds); break;
	case VCL_GRACE: VRT_l_beresp_grace(ctx, seconds); break;
	case VCL_KEEP:  VRT_l_beresp_keep(ctx, seconds); break;
	}
}

void
vclv_set_uncacheable(VRT_CTX)
{
	VRT_l_beresp_uncacheable(ctx, 1);
}

int
vclv_client_ip(VRT_CTX, unsigned char out[16])
{
	VCL_IP ip;
	const unsigned char *bytes;
	int family;

	ip = VRT_r_client_ip(ctx);
	if (ip == NULL)
		return (-1);
	family = VSA_GetPtr(ip, &bytes);
	if (family == PF_INET) {
		memset(out, 0, 10);
		out[10] = 0xff;
		out[11] = 0xff;
		memcpy(out + 12, bytes, 4);
		return (4);
	}
	if (family == PF_INET6) {
		memcpy(out, bytes, 16);
		return (6);
	}
	return (-1);
}

int
vclv_cache_status(VRT_CTX)
{
	if (ctx->method != VCL_MET_DELIVER)
		return (-1);
	if (VRT_r_obj_hits(ctx) <= 0)
		return (1);
	/* A hit on an object past its TTL is being served from grace. */
	return (VRT_r_obj_ttl(ctx) <= 0 ? 2 : 0);
}

int
vclv_set_reason(VRT_CTX, const char *reason, size_t len)
{
	char *copy;

	if (ctx->method != VCL_MET_SYNTH || len > INT_MAX)
		return (-1);
	CHECK_OBJ_NOTNULL(ctx->http_resp, HTTP_MAGIC);
	copy = WS_Copy(ctx->http_resp->ws, reason, (int)len + 1);
	if (copy == NULL)
		return (-1);
	copy[len] = '\0';
	http_SetH(ctx->http_resp, HTTP_HDR_REASON, copy);
	return (0);
}

int
vclv_synth_body(VRT_CTX, const char *body, size_t len)
{
	struct vsb *vsb;

	if (ctx->method != VCL_MET_SYNTH || len > INT_MAX)
		return (-1);
	vsb = (struct vsb *)ctx->specific;
	AN(vsb);
	VSB_clear(vsb);
	VSB_bcat(vsb, body, (ssize_t)len);
	return (0);
}

void
vclv_log(VRT_CTX, const char *msg, size_t len)
{
	if (ctx->vsl != NULL)
		VSLb(ctx->vsl, SLT_VCL_Log, "%.*s", (int)len, msg);
	else
		VSL(SLT_VCL_Log, 0, "%.*s", (int)len, msg);
}

void *
vclv_regex_compile(const char *pattern, const char **error)
{
#ifdef VARNISH_PLUS
	int error_offset = 0;
	*error = "";
	return (VRE_compile(pattern, 0, error, &error_offset));
#else
	int error_code = 0, error_offset = 0;
	vre_t *re;
	re = VRE_compile(pattern, 0, &error_code, &error_offset, 0);
	*error = re == NULL ? "invalid regular expression" : "";
	return (re);
#endif
}

void
vclv_regex_free(void *re)
{
	vre_t *vre = re;
	VRE_free(&vre);
}

int
vclv_regex_match(const void *re, const char *subject, size_t len)
{
	if (len > INT_MAX)
		return (0);
#ifdef VARNISH_PLUS
	return (VRE_exec(re, subject, (int)len, 0, 0, NULL, 0, NULL) >= 0);
#else
	return (VRE_match(re, subject, len, 0, NULL) >= 0);
#endif
}

const char *
vclv_regsub(VRT_CTX, int all, const char *subject, void *re,
    const char *replacement)
{
	return (VRT_regsub(ctx, all, subject, re, replacement));
}
