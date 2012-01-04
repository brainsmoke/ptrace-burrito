/* snippet from http://en.wikipedia.org/wiki/RDTSC
 * Thu Apr  3 02:44:50 CEST 2008
 */

#include <stdint.h>
#include <stdio.h>

uint64_t rdtsc() {
uint32_t lo, hi;
/* We cannot use "=A", since this would use %rax on x86_64 */
__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
return (uint64_t)hi << 32 | lo;
}

int main()
{
	printf("%llu\n", (unsigned long long)rdtsc());
}
