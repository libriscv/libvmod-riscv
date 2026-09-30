#pragma once
/**
 * The Varnish half of the VCL policy ABI.
 *
 * Everything here touches Varnish's own objects, so it is plain C compiled
 * against cache/cache.h: the header maps, the busy object's TTLs and the
 * delivered object's hit count are Varnish's structs, not mirrors of them.
 * The C++ side (vcl_syscalls.cpp) moves bytes in and out of guest memory
 * and calls down here with plain pointers and lengths.
 *
 * A `side` is which header map a phase means by "request" and "response":
 *
 *   method                request      response
 *   vcl_recv              req          -          (synth response is staged)
 *   vcl_deliver           req          resp
 *   vcl_synth             req          resp
 *   vcl_backend_fetch     bereq        -
 *   vcl_backend_response  bereq        beresp
 */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct vrt_ctx;
struct http;

enum vcl_side { VCL_SIDE_REQUEST = 0, VCL_SIDE_RESPONSE = 1 };

/* The phase the compiled policy is running, from ctx->method. */
enum vcl_phase {
	VCL_PHASE_NONE = 0,
	VCL_PHASE_RECV,
	VCL_PHASE_BACKEND_FETCH,
	VCL_PHASE_BACKEND_RESPONSE,
	VCL_PHASE_DELIVER,
	VCL_PHASE_SYNTH,
};
enum vcl_phase vclv_phase(const struct vrt_ctx *);

/* The header map a side means in the current phase, or NULL. */
struct http *vclv_http(const struct vrt_ctx *, enum vcl_side);

/* First value of a header, case-insensitively. Returns 0 and sets the
   value, or -1 when the header is absent. The value is not NUL-terminated
   for the caller's purposes; *vlen is its length. */
int vclv_get(const struct http *, const char *name, size_t nlen,
    const char **value, size_t *vlen);
/* Replace every value of a header with one. 0, or -1 on workspace exhaustion. */
int vclv_set(const struct vrt_ctx *, struct http *, const char *name, size_t nlen,
    const char *value, size_t vlen);
/* Append one more value of a header. */
int vclv_add(const struct vrt_ctx *, struct http *, const char *name, size_t nlen,
    const char *value, size_t vlen);
void vclv_unset(struct http *, const char *name, size_t nlen);

/* Walk a header map: each call yields the next "Name: value" field as a name
   and a value. *cursor starts at 0. Returns 0 while there are fields. */
int vclv_next(const struct http *, unsigned *cursor,
    const char **name, size_t *nlen, const char **value, size_t *vlen);

const char *vclv_url(const struct http *, size_t *len);
const char *vclv_method(const struct http *, size_t *len);
int vclv_set_url(const struct vrt_ctx *, struct http *, const char *url, size_t len);
unsigned vclv_status(const struct http *);

/* beresp.ttl, beresp.grace, beresp.keep in whole seconds. */
enum vcl_duration { VCL_TTL = 0, VCL_GRACE = 1, VCL_KEEP = 2 };
double vclv_get_duration(const struct vrt_ctx *, enum vcl_duration);
void vclv_set_duration(const struct vrt_ctx *, enum vcl_duration, double);
void vclv_set_uncacheable(const struct vrt_ctx *);

/* The client address as 16 bytes, IPv4 mapped into ::ffff:0:0/96.
   Returns 4 or 6 (the original family), or -1. */
int vclv_client_ip(const struct vrt_ctx *, unsigned char out[16]);

/* How the response vcl_deliver is about to send came to be: 0 hit,
   1 miss (a pass reads as one), 2 stale (a grace hit). -1 outside
   vcl_deliver. The numbers are the policy ABI's cache status. */
int vclv_cache_status(const struct vrt_ctx *);

/* Set the response reason phrase. vcl_synth only. */
int vclv_set_reason(const struct vrt_ctx *, const char *reason, size_t len);
/* Replace the synthetic response body. vcl_synth only. */
int vclv_synth_body(const struct vrt_ctx *, const char *body, size_t len);

void vclv_log(const struct vrt_ctx *, const char *msg, size_t len);

/* Regular expressions, compiled with Varnish's own engine so a pattern
   means in a compiled policy what it means in the VCL around it. */
void *vclv_regex_compile(const char *pattern, const char **error);
void vclv_regex_free(void *);
/* 1 match, 0 no match. */
int vclv_regex_match(const void *re, const char *subject, size_t len);
/* NUL-terminated result on the workspace, or NULL. */
const char *vclv_regsub(const struct vrt_ctx *, int all, const char *subject,
    void *re, const char *replacement);

#ifdef __cplusplus
}
#endif
