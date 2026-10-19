/* The tenant program the API fuzzer forks for every input.
   It only has to reach wait_for_requests(), and to give the harness
   memory and functions to point system call arguments at. */
#include "riscv_api.hpp"

/* Pointer arguments land in here. Three pages, so buffers can cross
   page boundaries, and the host sees non-sequential guest memory. */
extern "C" {
__attribute__((used, aligned(4096)))
char fuzz_scratch[3 * 4096];
}

/* foreach_header_field() callback: an honest guest flips 'deleted' on
   some entries, a hostile one rewrites the array. 'data' holds the
   replacement array, so the fuzzer can play both. */
struct guest_header_field {
	int      where;
	uint32_t index;
	bool     deleted;
	bool     foreach;
};
extern "C" __attribute__((used))
void fuzz_foreach(const char* data, guest_header_field* fields, int count)
{
	if (data == nullptr || count <= 0)
		return;
	char* dst = (char *)fields;
	for (long i = 0; i < count * (long)sizeof(guest_header_field); i++)
		dst[i] = data[i];
}

extern "C" __attribute__((used))
long fuzz_return(long a0)
{
	return a0;
}

extern "C" __attribute__((used))
void fuzz_spin()
{
	for (;;) asm volatile("" ::: "memory");
}

static void on_recv(int)
{
}

void start(int, char**)
{
	wait_for_requests(on_recv);
}
