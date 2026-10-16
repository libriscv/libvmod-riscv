#include <api.h>
#include <nlohmann/json.hpp>
#include <cstring>
#include <ctime>
namespace varnish = api;
using json = nlohmann::json;

/* HS256 JSON Web Tokens (RFC 7519) using native base64 and SHA-256.
   From VCL:
     set req.http.X-JWT-Sub = riscv.call("jwt_verify", req.http.Authorization);
     set req.http.X-Token = riscv.call("jwt_sign", "alice"); */
static constexpr std::string_view SECRET = "my-secret-key-for-varnish-CDN";
static constexpr long TOKEN_LIFETIME = 3600;
static constexpr unsigned B64URL = BASE64_FLAG_URL | BASE64_FLAG_NOPAD;

static std::string hmac_sha256(std::string_view key, std::string_view msg)
{
	std::array<uint8_t, 64> k {};
	if (key.size() > k.size()) {
		const auto digest = varnish::sha256(key);
		std::memcpy(k.data(), digest.data(), digest.size());
	} else {
		std::memcpy(k.data(), key.data(), key.size());
	}

	std::string inner(k.size() + msg.size(), '\0');
	for (size_t i = 0; i < k.size(); i++)
		inner[i] = k[i] ^ 0x36;
	std::memcpy(inner.data() + k.size(), msg.data(), msg.size());
	const auto inner_hash = varnish::sha256(inner);

	std::array<char, 64 + 32> outer;
	for (size_t i = 0; i < k.size(); i++)
		outer[i] = k[i] ^ 0x5c;
	std::memcpy(outer.data() + k.size(), inner_hash.data(), inner_hash.size());
	const auto mac = varnish::sha256({outer.data(), outer.size()});
	return std::string((const char*) mac.data(), mac.size());
}

static bool equal_constant_time(std::string_view a, std::string_view b)
{
	if (a.size() != b.size())
		return false;
	unsigned char diff = 0;
	for (size_t i = 0; i < a.size(); i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

static bool header_safe(std::string_view text)
{
	if (text.empty() || text.size() > 256)
		return false;
	for (const unsigned char c : text)
		if (c < 0x20 || c == 0x7f)
			return false;
	return true;
}

static const json* member(const json& obj, const char* key)
{
	const auto it = obj.find(key);
	return it != obj.end() ? &*it : nullptr;
}

static std::string jwt_encode(const json& claims)
{
	const std::string signing_input =
		varnish::base64_encode(R"({"alg":"HS256","typ":"JWT"})", B64URL)
		+ "." + varnish::base64_encode(claims.dump(), B64URL);
	return signing_input + "." + varnish::base64_encode(hmac_sha256(SECRET, signing_input), B64URL);
}

static std::optional<json> jwt_decode(std::string_view token, long now)
{
	const size_t dot1 = token.find('.');
	if (dot1 == token.npos)
		return std::nullopt;
	const size_t dot2 = token.find('.', dot1 + 1);
	if (dot2 == token.npos || token.find('.', dot2 + 1) != token.npos)
		return std::nullopt;

	/* Authenticate before parsing anything the client sent */
	const auto signature = varnish::base64_decode(token.substr(dot2 + 1), B64URL);
	if (!signature || !equal_constant_time(*signature, hmac_sha256(SECRET, token.substr(0, dot2))))
		return std::nullopt;

	const auto header = varnish::base64_decode(token.substr(0, dot1), B64URL);
	const auto payload = varnish::base64_decode(token.substr(dot1 + 1, dot2 - dot1 - 1), B64URL);
	if (!header || !payload)
		return std::nullopt;

	const json hdr = json::parse(*header, nullptr, false);
	if (!hdr.is_object())
		return std::nullopt;
	const json* alg = member(hdr, "alg");
	if (!alg || !alg->is_string() || alg->get_ref<const std::string&>() != "HS256")
		return std::nullopt;

	json claims = json::parse(*payload, nullptr, false);
	if (!claims.is_object())
		return std::nullopt;
	const json* exp = member(claims, "exp");
	if (!exp || !exp->is_number() || now >= exp->get<double>())
		return std::nullopt;
	const json* nbf = member(claims, "nbf");
	if (nbf && (!nbf->is_number() || now < nbf->get<double>()))
		return std::nullopt;
	const json* sub = member(claims, "sub");
	if (!sub || !sub->is_string() || !header_safe(sub->get_ref<const std::string&>()))
		return std::nullopt;
	return claims;
}

/* Returns the subject of a valid token, or NULL */
static const char* jwt_verify(const char* arg, size_t len)
{
	std::string_view token(arg, len);
	if (token.starts_with("Bearer "))
		token.remove_prefix(7);

	const auto claims = jwt_decode(token, std::time(nullptr));
	if (!claims)
		return nullptr;
	static std::string subject;
	subject = (*claims)["sub"].get<std::string>();
	return subject.c_str();
}

/* Returns a token for the subject, valid for TOKEN_LIFETIME */
static const char* jwt_sign(const char* arg, size_t len)
{
	const std::string_view subject(arg, len);
	if (!header_safe(subject))
		return nullptr;

	const long now = std::time(nullptr);
	static std::string token;
	token = jwt_encode({
		{"sub", subject},
		{"iat", now},
		{"exp", now + TOKEN_LIFETIME},
	});
	return token.c_str();
}

static void on_recv(varnish::Request)
{
}

int main()
{
	varnish::register_function("jwt_verify", jwt_verify);
	varnish::register_function("jwt_sign", jwt_sign);
	varnish::wait_for_requests(on_recv);
}
