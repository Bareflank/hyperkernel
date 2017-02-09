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

#ifndef PROCESS_INTEL_X64_H
#define PROCESS_INTEL_X64_H

#include <gsl/gsl>

#include <process/process.h>
#include <vmcs/root_ept_intel_x64.h>

class domain_intel_x64;

class process_intel_x64 : public process
{
public:

    using integer_pointer = uintptr_t;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    process_intel_x64(
        processid::type id,
        gsl::not_null<domain_intel_x64 *> domain);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~process_intel_x64() override = default;

    /// Init Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see process::init
    ///
    void init(user_data *data = nullptr) override;

    /// Fini Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @see process::fini
    ///
    void fini(user_data *data = nullptr) override;

    void vm_map(uintptr_t virt,
                uintptr_t phys,
                uintptr_t size,
                uintptr_t perm) override;

    void vm_map_lookup(uintptr_t virt,
                       uintptr_t rtpt,
                       uintptr_t addr,
                       uintptr_t size,
                       uintptr_t perm) override;

    void vm_map_page(uintptr_t virt,
                     uintptr_t phys,
                     uintptr_t perm);

    auto eptp() const
    { return m_root_ept->eptp(); }

private:

    gsl::not_null<domain_intel_x64 *> m_domain;
    std::unique_ptr<root_ept_intel_x64> m_root_ept;

public:

    friend class hyperkernel_ut;

    process_intel_x64(process_intel_x64 &&) = default;
    process_intel_x64 &operator=(process_intel_x64 &&) = default;

    process_intel_x64(const process_intel_x64 &) = delete;
    process_intel_x64 &operator=(const process_intel_x64 &) = delete;
};

#endif
