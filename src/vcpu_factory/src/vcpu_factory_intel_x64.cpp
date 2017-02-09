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

#include <vcpu_data_intel_x64.h>

#include <vcpu/vcpu_factory.h>
#include <vcpu/vcpu_intel_x64_hyperkernel.h>

#include <domain/domain_manager.h>
#include <domain/domain_intel_x64.h>

#include <vmcs/vmcs_intel_x64_hyperkernel.h>
#include <vmcs/vmcs_intel_x64_guest_vm_state.h>

#include <exit_handler/exit_handler_intel_x64_hyperkernel.h>

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, user_data *data)
{
    auto &&vd = dynamic_cast<vcpu_data_intel_x64 *>(data);
    expects(vd != nullptr);

    // Host vCPU
    //
    // This vCPU is created by the Host OS (which would be Windows, Linux or
    // something like UEFI for a type 1 configuration). This vCPU is only
    // created once per physical core, and you can view this vCPU as the
    // host vCPU, and it is unique in that, it's vcpuid's guest portion is
    // always 0. You should also view this as the root vCPU for this physical
    // core, as all other vCPUs are created from this one. As such, the
    // vcpuid == coreid
    //
    if (vd->m_is_host)
    {
        auto &&vmcs = std::make_unique<vmcs_intel_x64_hyperkernel>(
                          vd->m_coreid,
                          vcpuid,
                          vd->m_proclt,
                          vd->m_domain);

        auto &&exit_handler = std::make_unique<exit_handler_intel_x64_hyperkernel>(
                                  vd->m_coreid,
                                  vcpuid,
                                  vd->m_proclt,
                                  vd->m_domain);

        return std::make_unique<vcpu_intel_x64_hyperkernel>(
                   vd->m_coreid,
                   vcpuid,
                   vd->m_proclt,
                   vd->m_domain,
                   nullptr,                         // default debug_ring
                   nullptr,                         // default vmxon
                   std::move(vmcs),
                   std::move(exit_handler),
                   nullptr,                         // default vmm_state
                   nullptr);                        // default host_state
    }

    // Guest vCPU
    //
    // This vCPU is created from the context of the exit handler, which means
    // that it is always created from another vCPU (could be the root vCPU,
    // which is also called the host vCPU, or it could be created from another
    // guest vCPU likely from a call to `fork`). Since this is not the root
    // vCPU, we need to pass along information like the domain and coreid that
    // this vCPU belongs to.
    //
    else
    {
        auto &&vmcs = std::make_unique<vmcs_intel_x64_hyperkernel>(
                          vd->m_coreid,
                          vcpuid,
                          vd->m_proclt,
                          vd->m_domain);

        auto &&exit_handler = std::make_unique<exit_handler_intel_x64_hyperkernel>(
                                  vd->m_coreid,
                                  vcpuid,
                                  vd->m_proclt,
                                  vd->m_domain);

        auto &&guest_state = std::make_unique<vmcs_intel_x64_guest_vm_state>(
                                 vd->m_coreid,
                                 vcpuid,
                                 vd->m_proclt,
                                 vd->m_domain);

        return std::make_unique<vcpu_intel_x64_hyperkernel>(
                   vd->m_coreid,
                   vcpuid,
                   vd->m_proclt,
                   vd->m_domain,
                   nullptr,                         // default debug_ring
                   nullptr,                         // default vmxon
                   std::move(vmcs),
                   std::move(exit_handler),
                   nullptr,                         // default vmm_state
                   std::move(guest_state));
    }
}
