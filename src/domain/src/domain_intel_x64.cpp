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

#include <debug.h>
#include <upper_lower.h>

#include <domain/domain_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

#include <vcpu/vcpu_intel_x64_hyperkernel.h>

using namespace x64;

domain_intel_x64::domain_intel_x64(domainid::type id) :
    domain(id),
    m_vmapp_gdt{512},
    m_vmapp_idt{512},
    m_vmapp_tss{std::make_unique<uint64_t[]>(512)},
    m_root_pt{std::make_unique<root_page_table_x64>()}
{ }

void
domain_intel_x64::init(user_data *data)
{
    (void) data;

    m_gdt_base_phys = g_mm->virtint_to_physint(m_vmapp_gdt.base());
    m_idt_base_phys = g_mm->virtint_to_physint(m_vmapp_idt.base());
    m_tss_base_phys = g_mm->virtptr_to_physint(m_vmapp_tss.get());

    m_gdt_base_virt = 0x0000000100001000UL;
    m_idt_base_virt = 0x0000000100002000UL;
    m_tss_base_virt = 0x0000000100003000UL;

    expects(bfn::lower(m_gdt_base_phys) == 0);
    expects(bfn::lower(m_idt_base_phys) == 0);
    expects(bfn::lower(m_tss_base_phys) == 0);

    m_vmapp_gdt.set_access_rights(1, access_rights::ring0_cs_descriptor);
    m_vmapp_gdt.set_access_rights(2, access_rights::ring0_ss_descriptor);
    m_vmapp_gdt.set_access_rights(3, access_rights::ring0_fs_descriptor);
    m_vmapp_gdt.set_access_rights(4, access_rights::ring0_gs_descriptor);
    m_vmapp_gdt.set_access_rights(5, access_rights::ring0_tr_descriptor);

    m_vmapp_gdt.set_base(1, 0);
    m_vmapp_gdt.set_base(2, 0);
    m_vmapp_gdt.set_base(3, 0);
    m_vmapp_gdt.set_base(4, 0);
    m_vmapp_gdt.set_base(5, m_tss_base_virt);

    m_vmapp_gdt.set_limit(1, 0xFFFFFFFF);
    m_vmapp_gdt.set_limit(2, 0xFFFFFFFF);
    m_vmapp_gdt.set_limit(3, 0xFFFFFFFF);
    m_vmapp_gdt.set_limit(4, 0xFFFFFFFF);
    m_vmapp_gdt.set_limit(5, 0x1000);

    m_root_pt->setup_identity_map_1g(0x0, 0x100000000);

    /// TODO: Need to change the permissions of each entry such that they are
    /// set to U/S
    ///
    /// Can we use read-only?
    ///
    m_root_pt->map_4k(m_gdt_base_virt, m_gdt_base_virt, x64::memory_attr::rw_wb);
    m_root_pt->map_4k(m_idt_base_virt, m_idt_base_virt, x64::memory_attr::rw_wb);
    m_root_pt->map_4k(m_tss_base_virt, m_tss_base_virt, x64::memory_attr::rw_wb);

    m_cr3_mdl = m_root_pt->pt_to_mdl();

    bfdebug << "domain init: " << id() << '\n';
    domain::init(data);
}

void
domain_intel_x64::fini(user_data *data)
{
    bfdebug << "domain fini: " << id() << '\n';
    domain::fini(data);
}
