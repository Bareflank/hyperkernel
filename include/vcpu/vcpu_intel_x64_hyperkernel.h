//
// Bareflank Hypervisor
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

#ifndef VCPU_INTEL_X64_HYPERKERNEL_H
#define VCPU_INTEL_X64_HYPERKERNEL_H

#include <coreid.h>
#include <vcpuid.h>

#include <task/task.h>
#include <vcpu/vcpu_intel_x64.h>
#include <exit_handler/state_save_intel_x64.h>

class process_list;
class domain_intel_x64;
class thread_intel_x64;
class process_intel_x64;
class vmcs_intel_x64_hyperkernel;
class exit_handler_intel_x64_hyperkernel;

class vcpu_intel_x64_hyperkernel : public vcpu_intel_x64, public task
{
public:

    /// Constructor
    ///
    /// Creates a vCPU with the provided resources. This constructor
    /// provides a means to override and repalce the internal resources of the
    /// vCPU. Note that if one of the resources is set to NULL, a default
    /// will be constructed in its place, providing a means to select which
    /// internal components to override.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param coreid the id of the physical core
    /// @param vcpuid the id of the vcpu
    /// @param proclt the process list the vcpu should use.
    /// @param domain the domain the vcpu should use.
    /// @param debug_ring the debug ring the vcpu should use. If you
    ///     provide nullptr, a default debug ring will be created.
    /// @param vmxon the vmxon the vcpu should use. If you
    ///     provide nullptr, a default vmxon will be created.
    /// @param vmcs the vmcs the vcpu should use. If you
    ///     provide nullptr, a default vmcs will be created.
    /// @param exit_handler the exit handler the vcpu should use. If you
    ///     provide nullptr, a default exit handler will be created.
    /// @param vmm_state the vmm state the vcpu should use. If you
    ///     provide nullptr, a default vmm state will be created.
    /// @param guest_state the guest state the vcpu should use. If you
    ///     provide nullptr, a default guest state will be created.
    ///
    vcpu_intel_x64_hyperkernel(
        coreid::type coreid,
        vcpuid::type vcpuid,
        gsl::not_null<process_list *> proclt,
        gsl::not_null<domain_intel_x64 *> domain,
        std::unique_ptr<debug_ring> debug_ring = nullptr,
        std::unique_ptr<vmxon_intel_x64> vmxon = nullptr,
        std::unique_ptr<vmcs_intel_x64> vmcs = nullptr,
        std::unique_ptr<exit_handler_intel_x64> exit_handler = nullptr,
        std::unique_ptr<vmcs_intel_x64_state> vmm_state = nullptr,
        std::unique_ptr<vmcs_intel_x64_state> guest_state = nullptr);

    /// Destructor
    ///
    ~vcpu_intel_x64_hyperkernel() override = default;

    /// Init vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see vcpu::init
    ///
    void init(user_data *data = nullptr) override;

    /// Fini vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see vcpu::fini
    ///
    void fini(user_data *data = nullptr) override;

    /// Run vCPU
    ///
    /// @expects this->is_initialized() == true
    /// @ensures none
    ///
    /// @see vcpu::run
    ///
    void run(user_data *data = nullptr) override;

    /// Halt vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see vcpu::hlt
    ///
    void hlt(user_data *data = nullptr) override;

    /// Get Core ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the core id associated with this vCPU
    ///
    virtual coreid::type coreid() const
    { return m_coreid; }

    /// Get Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the process list associated with this vCPU
    ///
    virtual gsl::not_null<process_list *> get_proclt() const
    { return m_proclt; }

    /// Get Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the domain associated with this vCPU
    ///
    virtual gsl::not_null<domain_intel_x64 *> get_domain() const
    { return m_domain; }

    /// Schedule
    ///
    /// Executes this vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    void schedule() override;

    /// Schedule
    ///
    /// Executes this vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param thrd the thread to execute
    /// @param entry the entry function to execute
    /// @param arg1 the first arg to pass
    /// @param arg2 the second arg to pass
    ///
    void schedule(thread *thrd, uintptr_t entry, uintptr_t arg1, uintptr_t arg2) override;

    /// Schedule
    ///
    /// Executes this vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param proc the process to execute
    /// @param thrd the thread to execute
    /// @param state_save the state save for the process
    ///
    void schedule(process_intel_x64 *proc, thread_intel_x64 *thrd, state_save_intel_x64 *state_save);

    /// Next vCPU ID
    ///
    /// Unlike all of the other classes, vCPUs are actually managed by
    /// Bareflank itself. vCPU IDs need to be very specific for Bareflank
    /// as they also represent Core IDs, but the remaining vCPU ids can
    /// be arbitrary.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the next vCPU ID
    ///
    static vcpuid::type next_vcpuid();

private:

    coreid::type m_coreid;
    gsl::not_null<process_list *> m_proclt;
    gsl::not_null<domain_intel_x64 *> m_domain;

    gsl::not_null<vmcs_intel_x64_hyperkernel *> m_vmcs_hyperkernel;
    gsl::not_null<exit_handler_intel_x64_hyperkernel *> m_exit_handler_hyperkernel;

public:

    friend class hyperkernel_ut;

    vcpu_intel_x64_hyperkernel(vcpu_intel_x64_hyperkernel &&) = default;
    vcpu_intel_x64_hyperkernel &operator=(vcpu_intel_x64_hyperkernel &&) = default;

    vcpu_intel_x64_hyperkernel(const vcpu_intel_x64_hyperkernel &) = delete;
    vcpu_intel_x64_hyperkernel &operator=(const vcpu_intel_x64_hyperkernel &) = delete;
};

#endif
