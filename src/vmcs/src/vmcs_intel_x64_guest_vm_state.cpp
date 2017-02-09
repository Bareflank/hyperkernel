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

#include <upper_lower.h>
#include <vmcs/vmcs_intel_x64_guest_vm_state.h>

#include <intrinsics/msrs_x64.h>
#include <intrinsics/msrs_intel_x64.h>
#include <intrinsics/rflags_x64.h>

#include <memory_manager/pat_x64.h>
#include <domain/domain_intel_x64.h>

using namespace x64;
using namespace intel_x64;

vmcs_intel_x64_guest_vm_state::vmcs_intel_x64_guest_vm_state(
    coreid::type coreid,
    vcpuid::type vcpuid,
    gsl::not_null<process_list *> proclt,
    gsl::not_null<domain_intel_x64 *> domain) :

    m_coreid(coreid),
    m_vcpuid(vcpuid),
    m_proclt(proclt),
    m_domain(domain)
{
    (void) m_coreid;
    (void) m_vcpuid;
    (void) m_proclt;

    m_cs_index = 1;
    m_ss_index = 2;
    m_fs_index = 3;
    m_gs_index = 4;
    m_tr_index = 5;

    m_cs = gsl::narrow_cast<segment_register::type>(m_cs_index << 3);
    m_ss = gsl::narrow_cast<segment_register::type>(m_ss_index << 3);
    m_fs = gsl::narrow_cast<segment_register::type>(m_fs_index << 3);
    m_gs = gsl::narrow_cast<segment_register::type>(m_gs_index << 3);
    m_tr = gsl::narrow_cast<segment_register::type>(m_tr_index << 3);

    m_cr0 = 0;
    m_cr0 |= cr0::protection_enable::mask;
    m_cr0 |= cr0::monitor_coprocessor::mask;
    m_cr0 |= cr0::extension_type::mask;
    m_cr0 |= cr0::numeric_error::mask;
    m_cr0 |= cr0::write_protect::mask;
    m_cr0 |= cr0::paging::mask;

    m_cr3 = m_domain->cr3();

    m_cr4 = 0;
    m_cr4 |= cr4::physical_address_extensions::mask;
    m_cr4 |= cr4::page_global_enable::mask;
    m_cr4 |= cr4::vmx_enable_bit::mask;
    m_cr4 |= cr4::osfxsr::mask;
    m_cr4 |= cr4::osxsave::mask;

    // TODO: We need to set rflags to Ring 3 instead of Ring 0. Before we can
    // do this, we need to setup the GDT/IDT properly.
    //
    m_rflags = rflags::always_enabled::mask;

    m_ia32_pat_msr = x64::pat::pat_value;

    m_ia32_efer_msr = 0;
    m_ia32_efer_msr |= intel_x64::msrs::ia32_efer::lme::mask;
    m_ia32_efer_msr |= intel_x64::msrs::ia32_efer::lma::mask;
    m_ia32_efer_msr |= intel_x64::msrs::ia32_efer::nxe::mask;
}
