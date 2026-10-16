#include "script_functions.hpp"
#include "machine/syscalls.h"
#include <openssl/evp.h>
#include <array>
#include <cstring>
#include <memory>

namespace rvs {

static inline bool base64_alnum(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

void base64(machine_t& machine)
{
	auto [flags, src, dst, dstlen] =
		machine.sysargs<unsigned, riscv::Buffer, gaddr_t, gaddr_t> ();
	if (UNLIKELY(flags & ~unsigned(BASE64_FLAG_DECODE | BASE64_FLAG_URL | BASE64_FLAG_NOPAD))) {
		machine.set_result(-1);
		return;
	}
	machine.penalize(src.size());

	std::string copy;
	if (!src.is_sequential())
		copy = src.to_string();
	const auto* in = (const unsigned char*)(copy.empty() ? src.data() : copy.data());
	const size_t inlen = src.size();
	const bool url = flags & BASE64_FLAG_URL;
	const bool nopad = flags & BASE64_FLAG_NOPAD;

	std::array<unsigned char, 4096> stack;
	std::unique_ptr<unsigned char[]> heap;
	auto scratch = [&] (size_t n) -> unsigned char* {
		if (n <= stack.size())
			return stack.data();
		heap.reset(new unsigned char[n]);
		return heap.get();
	};

	if (!(flags & BASE64_FLAG_DECODE)) {
		const size_t enclen = (inlen + 2) / 3 * 4;
		const size_t outlen = nopad ? (inlen * 4 + 2) / 3 : enclen;
		if (UNLIKELY(outlen > dstlen)) {
			machine.set_result(-1);
			return;
		}
		auto* out = scratch(enclen + 1);
		EVP_EncodeBlock(out, in, int(inlen));
		if (url) {
			for (size_t i = 0; i < outlen; i++) {
				if (out[i] == '+') out[i] = '-';
				else if (out[i] == '/') out[i] = '_';
			}
		}
		if (outlen > 0)
			machine.copy_to_guest(dst, out, outlen);
		machine.set_result(outlen);
		return;
	}

	size_t len = inlen;
	size_t pad = 0;
	while (pad < 2 && len > 0 && in[len-1] == '=') {
		len--;
		pad++;
	}
	if (UNLIKELY((pad > 0 && (nopad || inlen % 4 != 0)) || len % 4 == 1)) {
		machine.set_result(-1);
		return;
	}
	const size_t outlen = len / 4 * 3 + (len % 4 ? len % 4 - 1 : 0);
	if (UNLIKELY(outlen > dstlen)) {
		machine.set_result(-1);
		return;
	}
	const size_t padded = (len + 3) & ~size_t(3);
	auto* buf = scratch(padded + padded / 4 * 3);
	auto* out = buf + padded;
	const unsigned char c62 = url ? '-' : '+';
	const unsigned char c63 = url ? '_' : '/';
	for (size_t i = 0; i < len; i++) {
		const unsigned char c = in[i];
		if (base64_alnum(c))
			buf[i] = c;
		else if (c == c62)
			buf[i] = '+';
		else if (c == c63)
			buf[i] = '/';
		else {
			machine.set_result(-1);
			return;
		}
	}
	std::memset(buf + len, '=', padded - len);
	if (UNLIKELY(EVP_DecodeBlock(out, buf, int(padded)) < 0)) {
		machine.set_result(-1);
		return;
	}
	if (outlen > 0)
		machine.copy_to_guest(dst, out, outlen);
	machine.set_result(outlen);
}

} // rvs
