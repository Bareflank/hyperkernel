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

#include <gsl/gsl>

#include <vcpu/vcpu_intel_x64_hyperkernel.h>
#include <vmcs/vmcs_intel_x64_hyperkernel.h>
#include <vmcs/vmcs_intel_x64_guest_vm_state.h>
#include <exit_handler/exit_handler_intel_x64_hyperkernel.h>

#include <domain/domain_intel_x64.h>

#include <scheduler/scheduler.h>
#include <scheduler/scheduler_manager.h>

#include <process/process.h>
#include <process/process_intel_x64.h>

#include <thread/thread.h>
#include <thread/thread_intel_x64.h>

#include <process_list/process_list.h>

vcpu_intel_x64_hyperkernel::vcpu_intel_x64_hyperkernel(
    coreid::type coreid,
    vcpuid::type vcpuid,
    gsl::not_null<process_list *> proclt,
    gsl::not_null<domain_intel_x64 *> domain,
    std::unique_ptr<debug_ring> debug_ring,
    std::unique_ptr<vmxon_intel_x64> vmxon,
    std::unique_ptr<vmcs_intel_x64> vmcs,
    std::unique_ptr<exit_handler_intel_x64> exit_handler,
    std::unique_ptr<vmcs_intel_x64_state> vmm_state,
    std::unique_ptr<vmcs_intel_x64_state> guest_state) :

    vcpu_intel_x64(
        vcpuid,
        std::move(debug_ring),
        std::move(vmxon),
        std::move(vmcs),
        std::move(exit_handler),
        std::move(vmm_state),
        std::move(guest_state)),

    task(
        coreid,
        vcpuid,
        proclt,
        domain),

    m_coreid(coreid),
    m_proclt(proclt),
    m_domain(domain),
    m_vmcs_hyperkernel(dynamic_cast<vmcs_intel_x64_hyperkernel *>(m_vmcs.get())),
    m_exit_handler_hyperkernel(dynamic_cast<exit_handler_intel_x64_hyperkernel *>(m_exit_handler.get()))
{ }

void
vcpu_intel_x64_hyperkernel::init(user_data *data)
{ vcpu_intel_x64::init(data); }

void
vcpu_intel_x64_hyperkernel::fini(user_data *data)
{ vcpu_intel_x64::fini(data); }

void
vcpu_intel_x64_hyperkernel::run(user_data *data)
{ vcpu_intel_x64::run(data); }

void
vcpu_intel_x64_hyperkernel::hlt(user_data *data)
{ vcpu_intel_x64::hlt(data); }

void
vcpu_intel_x64_hyperkernel::schedule()
{
    auto &&pair = m_proclt->next_job();

    auto &&thrd = dynamic_cast<thread_intel_x64 *>(std::get<0>(pair));
    auto &&proc = dynamic_cast<process_intel_x64 *>(std::get<1>(pair));

    schedule(proc, thrd, &thrd->m_state_save);
}

void
vcpu_intel_x64_hyperkernel::schedule(thread *thrd, uintptr_t entry, uintptr_t arg1, uintptr_t arg2)
{
    state_save_intel_x64 state_save = {};

    auto &&_thrd = dynamic_cast<thread_intel_x64 *>(thrd);
    auto &&_proc = dynamic_cast<process_intel_x64 *>(thrd->proc().get());

    state_save.rip = entry;
    state_save.rsp = _thrd->m_stack;
    state_save.rdi = arg1;
    state_save.rsi = arg2;

    schedule(_proc, _thrd, &state_save);
}

void
vcpu_intel_x64_hyperkernel::schedule(process_intel_x64 *proc, thread_intel_x64 *thrd, state_save_intel_x64 *state_save)
{
    // TODO:
    //
    // In v1.2, we need to break up the state save so that we are only copying
    // the bits that we need to.
    //

    if (thrd != nullptr)
    {
        auto old_vcpuid = m_state_save->vcpuid;
        auto old_vmxon_ptr = m_state_save->vmxon_ptr;
        auto old_vmcs_ptr = m_state_save->vmcs_ptr;
        auto old_exit_handler_ptr = m_state_save->exit_handler_ptr;

        *m_state_save = *state_save;

        m_state_save->vcpuid = old_vcpuid;
        m_state_save->vmxon_ptr = old_vmxon_ptr;
        m_state_save->vmcs_ptr = old_vmcs_ptr;
        m_state_save->exit_handler_ptr = old_exit_handler_ptr;

        if (this->is_running())
            m_vmcs_hyperkernel->set_eptp(proc->eptp());
        else
            m_state_save->user1 = proc->eptp();
    }

    m_exit_handler_hyperkernel->set_current_thread(thrd);
    run();
}

vcpuid::type
vcpu_intel_x64_hyperkernel::next_vcpuid()
{
    static vcpuid::type g_guest_vcpuids = (1UL << vcpuid::guest_from);
    return g_guest_vcpuids++;
}
