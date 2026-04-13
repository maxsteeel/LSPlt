#pragma once

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace lsplt::sys {

template <typename T = long>
inline T call(long n, long a1 = 0, long a2 = 0, long a3 = 0, long a4 = 0, long a5 = 0, long a6 = 0) {
    long r;
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    register long x8 __asm__("x8") = n;
    __asm__ __volatile__("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory");
    r = x0;
#elif defined(__arm__)
    register long r0 __asm__("r0") = a1;
    register long r1 __asm__("r1") = a2;
    register long r2 __asm__("r2") = a3;
    register long r3 __asm__("r3") = a4;
    register long r4 __asm__("r4") = a5;
    register long r5 __asm__("r5") = a6;
    register long r7 __asm__("r7") = n;
    __asm__ __volatile__("swi #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7) : "memory");
    r = r0;
#else
    r = syscall(n, a1, a2, a3, a4, a5, a6);
#endif
    return (T)r;
}

inline uintptr_t SysPageSize() { static const uintptr_t s = getpagesize(); return s; }
inline uintptr_t SysPageMask() { return ~(SysPageSize() - 1); }

inline void* mmap(void* a, size_t l, int p, int f, int d, off_t o) {
#if defined(__NR_mmap2)
    return call<void*>(__NR_mmap2, (long)a, (long)l, (long)p, (long)f, (long)d, (long)(o / 4096));
#else
    return call<void*>(__NR_mmap, (long)a, (long)l, (long)p, (long)f, (long)d, (long)o);
#endif
}

inline int mprotect(void* a, size_t l, int p) {
    return (int)call(__NR_mprotect, (long)a, (long)l, (long)p);
}

inline void* mremap(void* oa, size_t os, size_t ns, int f, void* na) {
    return call<void*>(__NR_mremap, (long)oa, (long)os, (long)ns, (long)f, (long)na);
}

} // namespace lsplt::sys
