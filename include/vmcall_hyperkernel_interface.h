/*
 * Bareflank Hyperkernel
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef VMCALL_HYPERKERNEL_INTERFACE_H
#define VMCALL_HYPERKERNEL_INTERFACE_H

#include <vmcall_interface.h>

#define REG_INVALID 0xFFFFFFFFFFFFFFFFUL
#define REG_CURRENT 0xFFFFFFFFFFFFFFF0UL
#define REG_SUCCESS 0x0

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __cplusplus
#define bool int
#endif

#ifndef __cplusplus
#define struct_init {0}
#else
#define struct_init {}
#endif

#ifndef __cplusplus
#define scast(a, b) ((a)(b))
#else
#define scast(a, b) (static_cast<a>(b))
#endif

void vmcall(struct vmcall_registers_t *regs);

enum hyperkernel_vmcall_functions
{
    hyperkernel_vmcall__create_process_list = 0x101,
    hyperkernel_vmcall__delete_process_list = 0x102,

    hyperkernel_vmcall__create_vcpu = 0x201,
    hyperkernel_vmcall__delete_vcpu = 0x202,

    hyperkernel_vmcall__create_process = 0x301,
    hyperkernel_vmcall__delete_process = 0x302,
    hyperkernel_vmcall__run_process = 0x303,
    hyperkernel_vmcall__hlt_process = 0x304,

    hyperkernel_vmcall__vm_map = 0x401,
    hyperkernel_vmcall__vm_map_lookup = 0x402,

    hyperkernel_vmcall__set_thread_info = 0x501,

    hyperkernel_vmcall__sched_yield = 0x1001,
    hyperkernel_vmcall__sched_yield_and_remove = 0x1002,

    hyperkernel_vmcall__set_program_break = 0x1101,
    hyperkernel_vmcall__increase_program_break = 0x1102,
    hyperkernel_vmcall__decrease_program_break = 0x1103,

    // TODO:
    //
    // These need to be made more generic
    //

    hyperkernel_vmcall__ttys0 = 0x2001,
    hyperkernel_vmcall__ttys1 = 0x2002,
    hyperkernel_vmcall__register_ttys0 = 0x3001,

};

inline uint64_t
vmcall__create_process_list(void)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__create_process_list;         // vmcall index
    regs.r03 = REG_CURRENT;                                     // domain id

    vmcall(&regs);

    if (regs.r01 == 0)
        return regs.r03;

    return REG_INVALID;
}

inline uint64_t
vmcall__create_foreign_process_list(uint64_t domainid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__create_process_list;         // vmcall index
    regs.r03 = domainid;                                        // domain id

    vmcall(&regs);

    if (regs.r01 == 0)
        return regs.r03;

    return REG_INVALID;
}

inline bool
vmcall__delete_process_list(uint64_t procltid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__delete_process_list;         // vmcall index
    regs.r03 = procltid;                                        // process list id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline uint64_t
vmcall__create_vcpu()
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__create_vcpu;                 // vmcall index
    regs.r03 = REG_CURRENT;                                     // process list id

    vmcall(&regs);

    if (regs.r01 == 0)
        return regs.r03;

    return REG_INVALID;
}

inline uint64_t
vmcall__create_foreign_vcpu(uint64_t procltid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__create_vcpu;                 // vmcall index
    regs.r03 = procltid;                                        // process list id

    vmcall(&regs);

    if (regs.r01 == 0)
        return regs.r03;

    return REG_INVALID;
}

inline bool
vmcall__delete_vcpu(uint64_t vcpuid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__delete_vcpu;                 // vmcall index
    regs.r03 = vcpuid;                                          // vcpu id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline uint64_t
vmcall__create_process()
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__create_process;              // vmcall index
    regs.r03 = REG_CURRENT;                                     // process list id

    vmcall(&regs);

    if (regs.r01 == 0)
        return regs.r03;

    return REG_INVALID;
}

inline uint64_t
vmcall__create_foreign_process(uint64_t procltid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__create_process;              // vmcall index
    regs.r03 = procltid;                                        // process list id

    vmcall(&regs);

    if (regs.r01 == 0)
        return regs.r03;

    return REG_INVALID;
}

inline bool
vmcall__delete_foreign_process(uint64_t procltid, uint64_t processid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__delete_process;              // vmcall index
    regs.r03 = procltid;                                        // process list id
    regs.r04 = processid;                                       // process id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__vm_map_foreign(
    uint64_t procltid,
    uint64_t processid,
    uint64_t virt,
    uint64_t phys,
    uint64_t size,
    uint64_t perm)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__vm_map;                      // vmcall index
    regs.r03 = procltid;                                        // process list id
    regs.r04 = processid;                                       // process id
    regs.r05 = virt;                                            // virtual address for the map
    regs.r06 = phys;                                            // physical address for the map
    regs.r07 = size;                                            // size of the map
    regs.r08 = perm;                                            // permissions

    vmcall(&regs);

    return regs.r01 == 0;
}

inline bool
vmcall__vm_map_foreign_lookup(
    uint64_t procltid,
    uint64_t processid,
    uint64_t virt,
    uint64_t addr,
    uint64_t size,
    uint64_t perm)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__vm_map_lookup;               // vmcall index
    regs.r03 = procltid;                                        // process list id
    regs.r04 = processid;                                       // process id
    regs.r05 = virt;                                            // virtual address for the map
    regs.r06 = addr;                                            // virtual address to lookup the physical addresses from
    regs.r07 = size;                                            // size of the map
    regs.r08 = perm;                                            // permissions

    vmcall(&regs);

    return regs.r01 == 0;
}

inline bool
vmcall__set_thread_info(
    uint64_t threadid,
    uint64_t entry,
    uint64_t stack,
    uint64_t arg1,
    uint64_t arg2)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__set_thread_info;             // vmcall index
    regs.r03 = REG_CURRENT;                                     // process list id
    regs.r04 = REG_CURRENT;                                     // process id
    regs.r05 = threadid;                                        // thread id
    regs.r06 = entry;
    regs.r07 = stack;
    regs.r08 = arg1;
    regs.r09 = arg2;

    vmcall(&regs);

    return regs.r01 == 0;
}

inline bool
vmcall__set_thread_foreign_info(
    uint64_t procltid,
    uint64_t processid,
    uint64_t threadid,
    uint64_t entry,
    uint64_t stack,
    uint64_t arg1,
    uint64_t arg2)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__set_thread_info;             // vmcall index
    regs.r03 = procltid;                                        // process list id
    regs.r04 = processid;                                       // process id
    regs.r05 = threadid;                                        // thread id
    regs.r06 = entry;
    regs.r07 = stack;
    regs.r08 = arg1;
    regs.r09 = arg2;

    vmcall(&regs);

    return regs.r01 == 0;
}

inline bool
vmcall__sched_yield()
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__sched_yield;                 // vmcall index

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__sched_yield_and_remove()
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__sched_yield_and_remove;      // vmcall index

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__set_program_break(uint64_t program_break)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__set_program_break;           // vmcall index
    regs.r03 = REG_CURRENT;                                     // process list id
    regs.r04 = REG_CURRENT;                                     // process id
    regs.r05 = program_break;

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__increase_program_break()
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__increase_program_break;      // vmcall index
    regs.r03 = REG_CURRENT;                                     // process list id
    regs.r04 = REG_CURRENT;                                     // process id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__increase_foreign_program_break(uint64_t procltid, uint64_t processid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__increase_program_break;      // vmcall index
    regs.r03 = procltid;                                        // process list id
    regs.r04 = processid;                                       // process id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__decrease_program_break()
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__decrease_program_break;      // vmcall index
    regs.r03 = REG_CURRENT;                                     // process list id
    regs.r04 = REG_CURRENT;                                     // process id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__decrease_foreign_program_break(uint64_t procltid, uint64_t processid)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__decrease_program_break;      // vmcall index
    regs.r03 = procltid;                                        // process list id
    regs.r04 = processid;                                       // process id

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__ttys0(char val)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__ttys0;
    regs.r03 = scast(uintptr_t, val);

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__ttys1(char val)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__ttys1;
    regs.r03 = scast(uintptr_t, val);

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

inline bool
vmcall__register_ttys0(uintptr_t func)
{
    struct vmcall_registers_t regs = struct_init;

    regs.r00 = VMCALL_REGISTERS;
    regs.r01 = VMCALL_MAGIC_NUMBER;
    regs.r02 = hyperkernel_vmcall__register_ttys0;
    regs.r03 = func;

    vmcall(&regs);

    return regs.r01 == REG_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
