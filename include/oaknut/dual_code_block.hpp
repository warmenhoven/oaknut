// SPDX-FileCopyrightText: Copyright (c) 2024 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <mach/mach.h>
#    include <mach/vm_map.h>

#    include <TargetConditionals.h>
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <unistd.h>
#    if TARGET_OS_IPHONE
#        include <signal.h>
#        include <sys/ucontext.h>
#    endif
#else
#    if !defined(_GNU_SOURCE)
#        define _GNU_SOURCE
#    endif
#    include <sys/mman.h>
#    include <sys/types.h>
#    include <unistd.h>
#endif

namespace oaknut {

#if defined(__APPLE__) && TARGET_OS_IPHONE
extern "C" int csops(int, unsigned int, void*, size_t);
#endif

class DualCodeBlock {
public:
    explicit DualCodeBlock(std::size_t size)
        : m_size(size)
    {
#if defined(_WIN32)
        m_wmem = m_xmem = (std::uint32_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (m_wmem == nullptr)
            throw std::bad_alloc{};
#elif defined(__APPLE__)
#if TARGET_OS_IPHONE
        auto has_cs_debugged = []() -> bool {
            int flags = 0;
            return !csops(0, 0 /*CS_OPS_STATUS*/, &flags, sizeof(flags)) && (flags & 0x10000000 /*CS_DEBUGGED*/);
        };
        bool use_brk_path = false;
        if (__builtin_available(iOS 26, *))
            use_brk_path = has_cs_debugged();
        if (use_brk_path) {
            // iOS 26+ with debugger: mmap R-X first, brk to bless pages, remap for R-W.
            // mprotect cannot add PROT_EXEC on iOS 26, so pages must start executable.
            m_xmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (m_xmem == MAP_FAILED)
                throw std::bad_alloc{};

            // Notify the debugger about the executable region.
            {
                static volatile bool s_brk_trapped;
                static struct sigaction s_prev_trap;
                struct sigaction trap_act = {};
                trap_act.sa_sigaction = [](int, siginfo_t*, void* ctx) {
                    s_brk_trapped = true;
                    ((ucontext_t*)ctx)->uc_mcontext->__ss.__pc += 4;
                };
                sigemptyset(&trap_act.sa_mask);
                trap_act.sa_flags = SA_SIGINFO;
                sigaction(SIGTRAP, &trap_act, &s_prev_trap);
                s_brk_trapped = false;
                __asm__ volatile(
                    "mov x0, %0\n"
                    "mov x1, %1\n"
                    "brk #0x69"
                    :: "r"(m_xmem), "r"(size)
                    : "x0", "x1", "memory"
                );
                sigaction(SIGTRAP, &s_prev_trap, nullptr);
            }

            vm_prot_t cur_prot, max_prot;
            kern_return_t ret = vm_remap(mach_task_self(), (vm_address_t*)&m_wmem, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, mach_task_self(), (mach_vm_address_t)m_xmem, false, &cur_prot, &max_prot, VM_INHERIT_NONE);
            if (ret != KERN_SUCCESS)
                throw std::bad_alloc{};

            mprotect(m_wmem, size, PROT_READ | PROT_WRITE);
        } else {
            // Pre-iOS 26: mmap R-W, remap, mprotect R-X. The debugger
            // attachment allows mprotect to add PROT_EXEC.
            m_wmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (m_wmem == MAP_FAILED)
                throw std::bad_alloc{};

            vm_prot_t cur_prot, max_prot;
            kern_return_t ret = vm_remap(mach_task_self(), (vm_address_t*)&m_xmem, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, mach_task_self(), (mach_vm_address_t)m_wmem, false, &cur_prot, &max_prot, VM_INHERIT_NONE);
            if (ret != KERN_SUCCESS)
                throw std::bad_alloc{};

            mprotect(m_xmem, size, PROT_READ | PROT_EXEC);
        }
#else
        // macOS: mmap R-X first, remap for R-W. No brk needed.
        m_xmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (m_xmem == MAP_FAILED)
            throw std::bad_alloc{};

        vm_prot_t cur_prot, max_prot;
        kern_return_t ret = vm_remap(mach_task_self(), (vm_address_t*)&m_wmem, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, mach_task_self(), (mach_vm_address_t)m_xmem, false, &cur_prot, &max_prot, VM_INHERIT_NONE);
        if (ret != KERN_SUCCESS)
            throw std::bad_alloc{};

        mprotect(m_wmem, size, PROT_READ | PROT_WRITE);
#endif
#else
#    if defined(__OpenBSD__)
        char tmpl[] = "oaknut_dual_code_block.XXXXXXXXXX";
        fd = shm_mkstemp(tmpl);
        if (fd < 0)
            throw std::bad_alloc{};
        shm_unlink(tmpl);
#    else
        fd = memfd_create("oaknut_dual_code_block", 0);
        if (fd < 0)
            throw std::bad_alloc{};
#    endif

        int ret = ftruncate(fd, size);
        if (ret != 0)
            throw std::bad_alloc{};

        m_wmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        m_xmem = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);

        if (m_wmem == MAP_FAILED || m_xmem == MAP_FAILED)
            throw std::bad_alloc{};
#endif
    }

    ~DualCodeBlock()
    {
#if defined(_WIN32)
        VirtualFree((void*)m_xmem, 0, MEM_RELEASE);
#elif defined(__APPLE__)
        munmap(m_xmem, m_size);
        vm_deallocate(mach_task_self(), (vm_address_t)m_wmem, m_size);
#else
        munmap(m_wmem, m_size);
        munmap(m_xmem, m_size);
        close(fd);
#endif
    }

    DualCodeBlock(const DualCodeBlock&) = delete;
    DualCodeBlock& operator=(const DualCodeBlock&) = delete;
    DualCodeBlock(DualCodeBlock&&) = delete;
    DualCodeBlock& operator=(DualCodeBlock&&) = delete;

    /// Pointer to executable mirror of memory (permissions: R-X)
    std::uint32_t* xptr() const
    {
        return m_xmem;
    }

    /// Pointer to writeable mirror of memory (permissions: RW-)
    std::uint32_t* wptr() const
    {
        return m_wmem;
    }

    /// Invalidate should be used with executable memory pointers.
    void invalidate(std::uint32_t* mem, std::size_t size)
    {
#if defined(__APPLE__)
        sys_icache_invalidate(mem, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), mem, size);
#else
        static std::size_t icache_line_size = 0x10000, dcache_line_size = 0x10000;

        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0"
                         : "=r"(ctr));

        const std::size_t isize = icache_line_size = std::min<std::size_t>(icache_line_size, 4 << ((ctr >> 0) & 0xf));
        const std::size_t dsize = dcache_line_size = std::min<std::size_t>(dcache_line_size, 4 << ((ctr >> 16) & 0xf));

        const std::uintptr_t end = (std::uintptr_t)mem + size;

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(dsize - 1); addr < end; addr += dsize) {
            __asm__ volatile("dc cvau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\n"
                         :
                         :
                         : "memory");

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(isize - 1); addr < end; addr += isize) {
            __asm__ volatile("ic ivau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n"
                         :
                         :
                         : "memory");
#endif
    }

    void invalidate_all()
    {
        invalidate(m_xmem, m_size);
    }

protected:
#if !defined(_WIN32) && !defined(__APPLE__)
    int fd = -1;
#endif
    std::uint32_t* m_xmem = nullptr;
    std::uint32_t* m_wmem = nullptr;
    std::size_t m_size = 0;
};

}  // namespace oaknut
