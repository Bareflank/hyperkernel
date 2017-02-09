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

#ifndef EXIT_HANDLER_INTEL_X64_HYPERKERNEL_H
#define EXIT_HANDLER_INTEL_X64_HYPERKERNEL_H

#include <gsl/gsl>

#include <coreid.h>
#include <vcpuid.h>
#include <domainid.h>

#include <vmcs/vmcs_intel_x64_hyperkernel.h>
#include <exit_handler/exit_handler_intel_x64_eapis.h>

class process_list;
class domain_intel_x64;
class process_intel_x64;

class exit_handler_intel_x64_hyperkernel : public exit_handler_intel_x64_eapis
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    exit_handler_intel_x64_hyperkernel(
        coreid::type coreid,
        vcpuid::type vcpuid,
        gsl::not_null<process_list *> proclt,
        gsl::not_null<domain_intel_x64 *> domain);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~exit_handler_intel_x64_hyperkernel() override = default;

    /// Get Core ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the core id associated with this exit handler
    ///
    virtual coreid::type coreid() const
    { return m_coreid; }

    /// Get vCPU ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vcpu id associated with this exit handler
    ///
    virtual vcpuid::type vcpuid() const
    { return m_vcpuid; }

    /// Get Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the process list associated with this exit handler
    ///
    virtual gsl::not_null<process_list *> get_proclt() const
    { return m_proclt; }

    /// Get Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the domain associated with this exit handler
    ///
    virtual gsl::not_null<domain_intel_x64 *> get_domain() const
    { return m_domain; }

    /// Set Current Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param proc the current process
    ///
    virtual void set_current_process(process_intel_x64 *proc)
    { m_process = proc; }

protected:

    void handle_exit(intel_x64::vmcs::value_type reason) override;
    void handle_vmcall_registers(vmcall_registers_t &regs) override;

    void create_process_list(vmcall_registers_t &regs);
    void delete_process_list(vmcall_registers_t &regs);

    void create_vcpu(vmcall_registers_t &regs);
    void delete_vcpu(vmcall_registers_t &regs);

    void create_process(vmcall_registers_t &regs);
    void delete_process(vmcall_registers_t &regs);

    void vm_map(vmcall_registers_t &regs);
    void vm_map_lookup(vmcall_registers_t &regs);

    void set_thread_info(vmcall_registers_t &regs);

    void sched_yield(vmcall_registers_t &regs);

    void set_program_break(vmcall_registers_t &regs);
    void increase_program_break(vmcall_registers_t &regs);
    void decrease_program_break(vmcall_registers_t &regs);

private:

    coreid::type m_coreid;
    vcpuid::type m_vcpuid;
    gsl::not_null<process_list *> m_proclt;
    gsl::not_null<domain_intel_x64 *> m_domain;

    process_intel_x64 *m_process;

public:

    friend class hyperkernel_ut;

    exit_handler_intel_x64_hyperkernel(exit_handler_intel_x64_hyperkernel &&) = default;
    exit_handler_intel_x64_hyperkernel &operator=(exit_handler_intel_x64_hyperkernel &&) = default;

    exit_handler_intel_x64_hyperkernel(const exit_handler_intel_x64_hyperkernel &) = delete;
    exit_handler_intel_x64_hyperkernel &operator=(const exit_handler_intel_x64_hyperkernel &) = delete;
};

#endif
