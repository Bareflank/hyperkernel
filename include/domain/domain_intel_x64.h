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

#ifndef DOMAIN_INTEL_X64_H
#define DOMAIN_INTEL_X64_H

#include <gsl/gsl>

#include <map>
#include <mutex>
#include <memory>

#include <intrinsics/tss_x64.h>
#include <intrinsics/gdt_x64.h>
#include <intrinsics/idt_x64.h>

#include <domain/domain.h>
#include <memory_manager/root_page_table_x64.h>

class domain_intel_x64 : public domain
{
public:

    using integer_pointer = uintptr_t;
    using memory_descriptor_list = root_page_table_x64::memory_descriptor_list;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    domain_intel_x64(domainid::type id);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~domain_intel_x64() override = default;

    /// Init Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see domain::init
    ///
    void init(user_data *data = nullptr) override;

    /// Fini Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see domain::fini
    ///
    void fini(user_data *data = nullptr) override;

    virtual integer_pointer cr3() const
    { return m_root_pt->cr3(); }

    virtual memory_descriptor_list &cr3_mdl()
    { return m_cr3_mdl; }

    virtual integer_pointer tss_base_phys() const
    { return m_tss_base_phys; }

    virtual integer_pointer gdt_base_phys() const
    { return m_gdt_base_phys; }

    virtual integer_pointer idt_base_phys() const
    { return m_idt_base_phys; }

    virtual integer_pointer tss_base_virt() const
    { return m_tss_base_virt; }

    virtual integer_pointer gdt_base_virt() const
    { return m_gdt_base_virt; }

    virtual integer_pointer idt_base_virt() const
    { return m_idt_base_virt; }

    virtual gsl::not_null<gdt_x64 *> gdt()
    { return &m_vmapp_gdt; }

    virtual gsl::not_null<idt_x64 *> idt()
    { return &m_vmapp_idt; }

private:

    gdt_x64 m_vmapp_gdt;
    idt_x64 m_vmapp_idt;
    std::unique_ptr<uint64_t[]> m_vmapp_tss;

    tss_x64::integer_pointer m_tss_base_phys;
    gdt_x64::integer_pointer m_gdt_base_phys;
    idt_x64::integer_pointer m_idt_base_phys;

    tss_x64::integer_pointer m_tss_base_virt;
    gdt_x64::integer_pointer m_gdt_base_virt;
    idt_x64::integer_pointer m_idt_base_virt;

    memory_descriptor_list m_cr3_mdl;
    std::unique_ptr<root_page_table_x64> m_root_pt;

public:

    friend class hyperkernel_ut;

    domain_intel_x64(domain_intel_x64 &&) = default;
    domain_intel_x64 &operator=(domain_intel_x64 &&) = default;

    domain_intel_x64(const domain_intel_x64 &) = delete;
    domain_intel_x64 &operator=(const domain_intel_x64 &) = delete;
};

#endif
