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

#include <vmcs/vmcs_intel_x64_hyperkernel.h>
#include <vmcs/vmcs_intel_x64_guest_vm_state.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

vmcs_intel_x64_hyperkernel::vmcs_intel_x64_hyperkernel(
    coreid::type coreid,
    vcpuid::type vcpuid,
    gsl::not_null<process_list *> proclt,
    gsl::not_null<domain_intel_x64 *> domain) :

    m_coreid(coreid),
    m_vcpuid(vcpuid),
    m_proclt(proclt),
    m_domain(domain)
{ }

void
vmcs_intel_x64_hyperkernel::write_fields(
    gsl::not_null<vmcs_intel_x64_state *> host_state,
    gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
    vmcs_intel_x64_eapis::write_fields(host_state, guest_state);

    this->enable_vpid();

    if (guest_state->is_guest())
    {
        primary_processor_based_vm_execution_controls::hlt_exiting::enable();

        // TODO:
        //
        // We should do some simple sanity checks on user1
        //

        this->enable_ept();
        this->set_eptp(m_state_save->user1);
    }
}
