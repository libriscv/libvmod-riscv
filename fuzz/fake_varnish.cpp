/* varnishd symbols the scripting API links against, rebuilt for the
   fuzzer. Where varnishd would assert or panic on a bad argument, so do
   these (modeled on Varnish 6.0 / Enterprise), because that is a crash
   the guest caused. Anything a guest cannot observe is left out. */
#include "fake_varnish.h"
#include <pcre.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>
#include "varnish.hpp"
extern "C" {
#include "varnish_interface.h"
}

#define FAKE_ASSERT(cond, ...) do { if (!(cond)) { \
	fprintf(stderr, "varnishd would panic: " __VA_ARGS__); \
	fprintf(stderr, " (%s:%d)\n", __FILE__, __LINE__); \
	abort(); } } while (0)

struct fake_ws {
	struct ws ws {};
	size_t size;
	size_t used = 0;
	bool   overflowed = false;
	std::vector<void*> blocks;
};
static fake_ws* state(struct ws* ws)
{
	FAKE_ASSERT(ws != nullptr && ws->magic == WS_MAGIC, "bad workspace");
	return (fake_ws *)ws;
}

namespace fake {
unsigned vrt_failures = 0;

struct ws* ws_new(size_t size)
{
	auto* fws = new fake_ws{.size = size};
	fws->ws.magic = WS_MAGIC;
	return &fws->ws;
}
void ws_delete(struct ws* ws)
{
	auto* fws = state(ws);
	for (void* p : fws->blocks)
		free(p);
	delete fws;
}

/* Varnish rolls req and bereq back to http0, the headers as received. */
struct http_copy {
	std::vector<txt> fields;
	std::vector<unsigned char> flags;
	uint16_t status;
};
static std::map<const struct http*, http_copy> snapshots;

static void snapshot_one(const struct http* hp)
{
	if (hp == nullptr)
		return;
	snapshots[hp] = {
		{hp->hd, hp->hd + hp->nhd},
		{hp->hdf, hp->hdf + hp->nhd},
		hp->status};
}
void snapshot_http(const struct vrt_ctx* ctx)
{
	snapshot_one(ctx->http_req);
	snapshot_one(ctx->http_bereq);
}
void forget_snapshots()
{
	snapshots.clear();
}

uint32_t touch_http(const struct http* hp)
{
	FAKE_ASSERT(hp->nhd <= hp->shd,
		"http has %u fields, room for %u", hp->nhd, hp->shd);
	uint32_t sum = 0;
	for (unsigned i = 0; i < hp->nhd; i++) {
		const txt& t = hp->hd[i];
		if (t.b == nullptr)
			continue;
		FAKE_ASSERT(t.e >= t.b, "header field %u ends before it begins", i);
		for (const char* p = t.b; p < t.e; p++)
			sum = sum * 31 + (unsigned char)*p;
	}
	return sum;
}
} // fake

/* ---------- Workspace ---------- */

static void* ws_take(struct ws* real_ws, size_t bytes)
{
	auto* ws = state(real_ws);
	const size_t rounded = (bytes + 7) & ~size_t(7);
	if (ws->overflowed || rounded > ws->size - ws->used) {
		ws->overflowed = true;
		return nullptr;
	}
	void* p = malloc(bytes > 0 ? bytes : 1);
	if (p == nullptr)
		abort();
	ws->used += rounded;
	ws->blocks.push_back(p);
	return p;
}

extern "C" void* WS_Alloc(struct ws* ws, unsigned bytes)
{
	return ws_take(ws, bytes);
}
extern "C" void* riscv_ws_alloc_spare(struct ws* ws, unsigned bytes, unsigned keep)
{
	const auto* fws = state(ws);
	if (fws->overflowed || size_t(bytes) + keep > fws->size - fws->used)
		return nullptr;
	return ws_take(ws, bytes);
}
extern "C" void* WS_Copy(struct ws* ws, const void* str, int len)
{
	if (len == -1)
		len = strlen((const char *)str) + 1;
	FAKE_ASSERT(len >= 0, "WS_Copy length %d", len);
	void* p = ws_take(ws, len);
	if (p != nullptr)
		memcpy(p, str, len);
	return p;
}
extern "C" void* WS_Printf(struct ws* ws, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	const int len = vsnprintf(nullptr, 0, fmt, ap);
	va_end(ap);
	char* p = (char *)ws_take(ws, len + 1);
	if (p == nullptr)
		return nullptr;
	va_start(ap, fmt);
	vsnprintf(p, len + 1, fmt, ap);
	va_end(ap);
	return p;
}

/* ---------- Logging: format everything, so ASan checks the arguments ---------- */

static void vsl_format(const char* fmt, va_list ap)
{
	char buffer[2048];
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
}
extern "C" void VSLb(struct vsl_log*, enum VSL_tag_e, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsl_format(fmt, ap);
	va_end(ap);
}
extern "C" void VSL(enum VSL_tag_e, uint32_t, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsl_format(fmt, ap);
	va_end(ap);
}
extern "C" void VSLbt(struct vsl_log*, enum VSL_tag_e, txt t)
{
	volatile unsigned char sum = 0;
	for (const char* p = t.b; p < t.e; p++)
		sum += *p;
}

/* ---------- HTTP ---------- */

extern "C" void http_SetH(struct http* to, unsigned n, const char* fm)
{
	FAKE_ASSERT(n < to->nhd, "http_SetH index %u of %u", n, to->nhd);
	FAKE_ASSERT(fm != nullptr, "http_SetH NULL value");
	to->hd[n].b = fm;
	to->hd[n].e = strchr(fm, '\0');
	to->hdf[n] = 0;
}

extern "C" void http_PrintfHeader(struct http* to, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	const int len = vsnprintf(nullptr, 0, fmt, ap);
	va_end(ap);
	char* p = (char *)ws_take(to->ws, len + 1);
	if (p == nullptr || to->nhd >= to->shd)
		return; /* SLT_LostHeader */
	va_start(ap, fmt);
	vsnprintf(p, len + 1, fmt, ap);
	va_end(ap);
	const unsigned n = to->nhd++;
	to->hd[n].b = p;
	to->hd[n].e = p + len;
	to->hdf[n] = 0;
}

extern "C" void http_SetStatus(struct http* to, uint16_t status)
{
	/* "We allow people to use top digits for internal VCL
	   signalling, but strip them from the ASCII version." */
	to->status = status;
	status %= 1000;
	FAKE_ASSERT(status >= 100, "http_SetStatus(%u)", to->status);
	char* s = (char *)WS_Printf(to->ws, "%03u", status);
	if (s != nullptr)
		http_SetH(to, 3, s);
	http_SetH(to, 4, "Reason");
}

/* ---------- VRT ---------- */

extern "C" void VRT_fail(const struct vrt_ctx*, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsl_format(fmt, ap);
	va_end(ap);
	fake::vrt_failures++;
}

extern "C" void VRT_ban_string(const struct vrt_ctx*, const char* str)
{
	FAKE_ASSERT(str != nullptr, "VRT_ban_string(NULL)");
	volatile size_t len = strlen(str);
	(void)len;
}

extern "C" void VRT_Rollback(const struct vrt_ctx* ctx, VCL_HTTP hp)
{
	FAKE_ASSERT(hp == ctx->http_req || hp == ctx->http_bereq,
		"VRT_Rollback 'hp' invalid");
	FAKE_ASSERT(hp != ctx->http_req || ctx->req != nullptr, "rollback without req");
	FAKE_ASSERT(hp != ctx->http_bereq || ctx->bo != nullptr, "rollback without bo");
	auto it = fake::snapshots.find(hp);
	FAKE_ASSERT(it != fake::snapshots.end(), "rollback without http0");
	auto* to = const_cast<struct http*>(hp);
	const auto& from = it->second;
	memcpy(to->hd, from.fields.data(), from.fields.size() * sizeof(txt));
	memcpy(to->hdf, from.flags.data(), from.flags.size());
	to->nhd = from.fields.size();
	to->status = from.status;
}

extern "C" struct vmod_priv* VRT_priv_task(const struct vrt_ctx*, const void*)
{
	static struct vmod_priv priv;
	return &priv;
}

/* Only VCL programs register counters, and the harness runs none */
extern "C" void* VRT_VSC_Alloc(struct vsmw_cluster*, struct vsc_seg**,
	const char*, size_t, const unsigned char*, size_t, const char*, ...)
{
	FAKE_ASSERT(false, "VRT_VSC_Alloc is not expected here");
}

/* ---------- varnish_interface.c ---------- */

extern "C" void riscv_SetHash(struct req* req, VSHA256_CTX* ctx)
{
	VSHA256_Final(((fake::req *)req)->digest, ctx);
}
static fake::busyobj* busyobj(const struct vrt_ctx* ctx)
{
	FAKE_ASSERT(ctx->bo != nullptr, "CHECK_OBJ_NOTNULL(ctx->bo)");
	return (fake::busyobj *)ctx->bo;
}
extern "C" void riscv_SetCacheable(const struct vrt_ctx* ctx, bool c)
{
	auto* bo = busyobj(ctx);
	if (!(bo->uncacheable && c))
		bo->uncacheable = !c;
}
extern "C" bool riscv_GetCacheable(const struct vrt_ctx* ctx)
{
	return !busyobj(ctx)->uncacheable;
}
extern "C" void riscv_SetTTL(const struct vrt_ctx* ctx, float ttl)
{
	busyobj(ctx)->ttl = ttl;
}
extern "C" float riscv_GetTTL(const struct vrt_ctx* ctx)
{
	return busyobj(ctx)->ttl;
}
extern "C" long riscv_SetBackend(const struct vrt_ctx* ctx, VCL_BACKEND dir)
{
	if (ctx->req != nullptr) {
		((fake::req *)ctx->req)->director_hint = dir;
		return 0;
	} else if (ctx->bo != nullptr) {
		((fake::busyobj *)ctx->bo)->director_req = dir;
		return 0;
	}
	return -1;
}

/* ---------- VRE: PCRE1, as in Varnish 6.0 ---------- */

struct vre {
	pcre*       re;
	pcre_extra* extra;
};
extern "C" const unsigned VRE_has_jit = 0;
extern "C" const unsigned VRE_CASELESS = PCRE_CASELESS;
extern "C" const unsigned VRE_NOTEMPTY = PCRE_NOTEMPTY;

extern "C" vre_t* VRE_compile(const char* pattern, unsigned options,
	const char** errptr, int* erroffset)
{
	pcre* re = pcre_compile(pattern, options, errptr, erroffset, nullptr);
	if (re == nullptr)
		return nullptr;
	pcre_extra* extra = pcre_study(re, 0, errptr);
	if (extra == nullptr)
		extra = (pcre_extra *)calloc(1, sizeof(pcre_extra));
	return new vre{re, extra};
}
extern "C" int VRE_exec(const vre_t* code, const char* subject, int length,
	int startoffset, int options, int* ovector, int ovecsize,
	const volatile struct vre_limits* lim)
{
	int ov[30];
	FAKE_ASSERT(code != nullptr, "VRE_exec(NULL)");
	if (ovector == nullptr) {
		ovector = ov;
		ovecsize = sizeof(ov) / sizeof(ov[0]);
	}
	if (lim != nullptr) {
		code->extra->match_limit = lim->match;
		code->extra->match_limit_recursion = lim->match_recursion;
		code->extra->flags |= PCRE_EXTRA_MATCH_LIMIT
			| PCRE_EXTRA_MATCH_LIMIT_RECURSION;
	}
	return pcre_exec(code->re, code->extra, subject, length,
		startoffset, options, ovector, ovecsize);
}
extern "C" void VRE_free(vre_t** vv)
{
	vre_t* v = *vv;
	*vv = nullptr;
	if (v == nullptr)
		return;
	pcre_free_study(v->extra);
	pcre_free(v->re);
	delete v;
}

/* ---------- VSHA256: a real SHA-256, so the harness can check results ---------- */

static const uint32_t K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_block(uint32_t state[8], const unsigned char* p)
{
	uint32_t w[64];
	for (int i = 0; i < 16; i++)
		w[i] = uint32_t(p[4*i]) << 24 | uint32_t(p[4*i+1]) << 16
			| uint32_t(p[4*i+2]) << 8 | p[4*i+3];
	for (int i = 16; i < 64; i++) {
		const uint32_t s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3);
		const uint32_t s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
	for (int i = 0; i < 64; i++) {
		const uint32_t t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25))
			+ ((e & f) ^ (~e & g)) + K256[i] + w[i];
		const uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22))
			+ ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

extern "C" void VSHA256_Init(VSHA256_CTX* ctx)
{
	static const uint32_t H0[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	memcpy(ctx->state, H0, sizeof(H0));
	ctx->count = 0;
}
extern "C" void VSHA256_Update(VSHA256_CTX* ctx, const void* in, size_t len)
{
	const unsigned char* p = (const unsigned char *)in;
	while (len > 0) {
		const size_t fill = ctx->count % 64;
		const size_t n = len < 64 - fill ? len : 64 - fill;
		memcpy(ctx->buf + fill, p, n);
		ctx->count += n;
		p += n;
		len -= n;
		if (ctx->count % 64 == 0)
			sha256_block(ctx->state, ctx->buf);
	}
}
extern "C" void VSHA256_Final(unsigned char digest[32], VSHA256_CTX* ctx)
{
	const uint64_t bits = ctx->count * 8;
	static const unsigned char pad[64] = {0x80};
	const size_t fill = ctx->count % 64;
	VSHA256_Update(ctx, pad, fill < 56 ? 56 - fill : 120 - fill);
	unsigned char len[8];
	for (int i = 0; i < 8; i++)
		len[i] = bits >> (56 - 8 * i);
	VSHA256_Update(ctx, len, 8);
	for (int i = 0; i < 8; i++) {
		digest[4*i]   = ctx->state[i] >> 24;
		digest[4*i+1] = ctx->state[i] >> 16;
		digest[4*i+2] = ctx->state[i] >> 8;
		digest[4*i+3] = ctx->state[i];
	}
}
