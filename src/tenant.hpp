#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace rvs {
/* C++20 deprecates the std::atomic_* free functions for shared_ptr in favor
   of std::atomic<std::shared_ptr<T>>, which GCC 11 (EL9, AL2023) lacks. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
template <typename T>
inline std::shared_ptr<T> atomic_load(const std::shared_ptr<T>* p) {
	return std::atomic_load(p);
}
template <typename T>
inline void atomic_store(std::shared_ptr<T>* p, std::type_identity_t<std::shared_ptr<T>> v) {
	std::atomic_store(p, std::move(v));
}
template <typename T>
inline std::shared_ptr<T> atomic_exchange(std::shared_ptr<T>* p, std::type_identity_t<std::shared_ptr<T>> v) {
	return std::atomic_exchange(p, std::move(v));
}
#pragma GCC diagnostic pop

struct TenantGroup {
	uint64_t max_instructions  = 20'000'000ull;
	uint32_t max_memory_mb     = 32; // 32MB
	uint32_t max_heap_mb       = 512; // 512MB
	size_t   max_backends = 8;
	size_t   max_regex    = 32;
	bool	 verbose      = false;

	/* Atomically swappable: readers snapshot this shared_ptr, writers
	   create a new vector and exchange the pointer. */
	std::shared_ptr<std::vector<std::string>> argv =
		std::make_shared<std::vector<std::string>>();
};

struct TenantConfig
{
	std::string    name;
	std::string    filename;
	TenantGroup    group;

	uint64_t max_instructions() const noexcept { return group.max_instructions; }
	uint64_t max_memory() const noexcept { return uint64_t(group.max_memory_mb) << 20; }
	uint64_t max_heap() const noexcept { return uint64_t(group.max_heap_mb) << 20; }
	size_t   max_regex() const noexcept { return group.max_regex; }
	size_t   max_backends() const noexcept { return group.max_backends; }
	bool     elf_execute_only() const noexcept { return false; }

	TenantConfig(std::string n, std::string f, TenantGroup g)
		: name(n), filename(f), group{std::move(g)} {}
};

} // rvs
