//
// Bareflank Hyperkernel
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

//
// Bareflank C Library
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <stddef.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/times.h>
#include <regex.h>

#include <crt.h>
#include <constants.h>
#include <eh_frame_list.h>

#include <serial_x64.h>
#include <vmcall_hyperkernel_interface.h>

#define UNHANDLED() \
    { \
        const char *str_text = "\033[1;33mWARNING\033[0m: unsupported libc function called = "; \
        const char *str_func = __PRETTY_FUNCTION__; \
        const char *str_endl = "\n"; \
        write(0, str_text, strlen(str_text)); \
        write(0, str_func, strlen(str_func)); \
        write(0, str_endl, strlen(str_endl)); \
        hlt_cpu(); \
    }

extern "C" void hlt_cpu(void);
extern "C" void vmcall(struct vmcall_registers_t *regs);
extern "C" void vmcall_event(struct vmcall_registers_t *regs);

typedef void (*init_t)();
typedef void (*fini_t)();

extern "C" clock_t
times(struct tms *buf)
{
    (void) buf;

    UNHANDLED();

    return 0;
}

extern "C" int
execve(const char *path, char *const argv[], char *const envp[])
{
    (void) path;
    (void) argv;
    (void) envp;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
getpid(void)
{
    UNHANDLED();

    return 0;
}

extern "C" int
isatty(int fd)
{
    (void) fd;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" off_t
lseek(int fd, off_t offset, int whence)
{
    (void) fd;
    (void) offset;
    (void) whence;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
_init(void)
{ }

extern "C" int
kill(pid_t _pid, int _sig)
{
    (void) _pid;
    (void) _sig;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
wait(int *status)
{
    (void) status;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" _READ_WRITE_RETURN_TYPE
read(int fd, void *buffer, size_t length)
{
    (void) fd;
    (void) buffer;
    (void) length;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
unlink(const char *file)
{
    (void) file;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
fork(void)
{
    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
regcomp(regex_t *preg, const char *regex, int cflags)
{
    (void) preg;
    (void) regex;
    (void) cflags;

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" int
gettimeofday(struct timeval *tp, void *tzp)
{
    (void) tp;
    (void) tzp;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
clock_gettime(clockid_t clk_id, struct timespec *tp) __THROW
{
    (void) clk_id;
    (void) tp;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
regexec(const regex_t *preg, const char *string,
        size_t nmatch, regmatch_t pmatch[], int eflags)
{
    (void) preg;
    (void) string;
    (void) nmatch;
    (void) pmatch;
    (void) eflags;

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" void
_fini(void)
{ }

extern "C" int
stat(const char *pathname, struct stat *buf)
{
    (void) pathname;
    (void) buf;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
link(const char *oldpath, const char *newpath)
{
    (void) oldpath;
    (void) newpath;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
_exit(int status)
{
    (void) status;

    hlt_cpu();
    while (1);
}

extern "C" int
open(const char *file, int mode, ...)
{
    (void) file;
    (void) mode;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
regfree(regex_t *preg)
{
    UNHANDLED();

    (void) preg;
}

extern "C" int
fcntl(int fd, int cmd, ...)
{
    (void) fd;
    (void) cmd;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
mkdir(const char *path, mode_t mode)
{
    (void) path;
    (void) mode;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
    (void) memptr;
    (void) alignment;
    (void) size;

    UNHANDLED();

    return 0;
}

extern "C" int
close(int fd)
{
    (void) fd;

    // UNHANDLED();

    // errno = -ENOSYS;
    // return -1;

    return 0;
}

extern "C" int
sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    (void) how;
    (void) set;
    (void) oldset;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" long
sysconf(int name)
{
    (void) name;

    UNHANDLED();

    errno = -EINVAL;
    return -1;
}

extern "C" int
nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void) req;
    (void) rem;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
getentropy(void *buf, size_t buflen)
{
    (void) buf;
    (void) buflen;

    UNHANDLED();

    errno = -EIO;
    return -1;
}

extern "C" int
__fpclassifyf(float)
{ return 0; }

extern "C" int
__fpclassifyd(double)
{ return 0; }

extern "C" double
ldexp(double x, int exp)
{ return __builtin_ldexp(x, exp); }

extern "C" float
nanf(const char *tagp)
{ return __builtin_nanf(tagp); }


namespace std
{
void terminate()
{ }
}

extern "C" void
__cxa_end_catch(void)
{ }

extern "C" void
__cxa_begin_catch(void)
{ }

extern "C" void
__gxx_personality_v0(void)
{ }

extern "C" int
write(int file, const void *buffer, size_t count)
{
    (void) file;

    if (buffer == nullptr || count == 0)
        return 0;

    try
    {
        serial_x64::instance()->write(static_cast<const char *>(buffer), count);
        return static_cast<int>(count);
    }
    catch (...) { }

    return 0;
}

extern "C" int
fstat(int file, struct stat *sbuf)
{
    (void) file;
    (void) sbuf;

    errno = -ENOSYS;
    return -1;
}

uintptr_t __stack_chk_guard = 0x595e9fbd94fda766;

extern "C" void
__stack_chk_fail(void) noexcept
{
    auto msg = "__stack_chk_fail: buffer overflow in vmapp detected!!!\n";
    write(1, msg, strlen(msg));
    abort();
}

uintptr_t g_program_break = 0;
uintptr_t g_program_cursor = 0;

extern "C" int
set_program_break(uint64_t program_break)
{
    g_program_break = program_break;
    g_program_cursor = program_break;

    if (vmcall__set_program_break(program_break))
        return 0;

    return -1;
}

extern "C" void *
sbrk(ptrdiff_t inc)
{
    g_program_cursor += static_cast<uintptr_t>(inc);

    while (g_program_break < g_program_cursor)
    {
        if (!vmcall__increase_program_break())
        {
            errno = ENOMEM;
            return reinterpret_cast<void *>(-1);
        }

        g_program_break += 0x1000;
    }

    return reinterpret_cast<void *>(g_program_cursor - static_cast<uintptr_t>(inc));
}

extern "C" int64_t
local_init(struct section_info_t *info)
{
    if (info == nullptr)
        return CRT_FAILURE;

    try
    {
        if (info->init_addr != nullptr)
            reinterpret_cast<init_t>(info->init_addr)();

        if (info->init_array_addr != nullptr)
        {
            auto n = static_cast<ptrdiff_t>(info->init_array_size >> 3);
            auto init_array = static_cast<init_t *>(info->init_array_addr);

            for (auto i = 0U; i < n && init_array[i] != nullptr; i++)
                init_array[i]();
        }
    }
    catch (...)
    {
        return CRT_FAILURE;
    }

    auto ret = register_eh_frame(info->eh_frame_addr, info->eh_frame_size);
    if (ret != REGISTER_EH_FRAME_SUCCESS)
        return ret;

    return CRT_SUCCESS;
}

extern "C" int64_t
local_fini(struct section_info_t *info)
{
    if (info == nullptr)
        return CRT_FAILURE;

    try
    {
        if (info->fini_array_addr != nullptr)
        {
            auto n = static_cast<ptrdiff_t>(info->fini_array_size >> 3);
            auto fini_array = static_cast<fini_t *>(info->fini_array_addr);

            for (auto i = 0U; i < n && fini_array[i] != nullptr; i++)
                fini_array[i]();
        }

        if (info->fini_addr != nullptr)
            reinterpret_cast<fini_t>(info->fini_addr)();
    }
    catch (...)
    {
        return CRT_FAILURE;
    }

    return CRT_SUCCESS;
}

auto g_eh_frame_list_num = 0ULL;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{ return g_eh_frame_list; }

extern "C" int64_t
register_eh_frame(void *addr, uint64_t size) noexcept
{
    if (addr == nullptr || size == 0)
        return REGISTER_EH_FRAME_SUCCESS;

    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return REGISTER_EH_FRAME_FAILURE;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;

    return REGISTER_EH_FRAME_SUCCESS;
}

extern "C" int
___xpg_strerror_r(int errnum, char *buf, size_t buflen)
{
    (void) errnum;

    __builtin_memset(buf, 0, buflen);
    return 0;
}

extern "C" int
sched_yield(void)
{ return 0; }

extern "C" char *
getwd(char *buf)
{
    (void) buf;

    UNHANDLED();

    return nullptr;
}

extern "C" char *
getcwd(char *buf, size_t size)
{
    (void) buf;
    (void) size;

    UNHANDLED();

    return nullptr;
}

extern "C" struct passwd *
getpwnam(const char *name)
{
    (void) name;

    UNHANDLED();

    return nullptr;
}
