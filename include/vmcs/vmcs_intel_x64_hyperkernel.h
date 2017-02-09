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

#ifndef VMCS_INTEL_X64_HYPERKERNEL_H
#define VMCS_INTEL_X64_HYPERKERNEL_H

#include <gsl/gsl>

#include <coreid.h>
#include <vcpuid.h>
#include <vmcs/vmcs_intel_x64_eapis.h>

class process_list;
class domain_intel_x64;

class vmcs_intel_x64_hyperkernel : public vmcs_intel_x64_eapis
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vmcs_intel_x64_hyperkernel(
        coreid::type coreid,
        vcpuid::type vcpuid,
        gsl::not_null<process_list *> proclt,
        gsl::not_null<domain_intel_x64 *> domain);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcs_intel_x64_hyperkernel() override  = default;

    /// Get Core ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the core id associated with this vmcs
    ///
    virtual coreid::type coreid() const
    { return m_coreid; }

    /// Get vCPU ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vcpu id associated with this vmcs
    ///
    virtual vcpuid::type vcpuid() const
    { return m_vcpuid; }

    /// Get Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the process list associated with this vmcs
    ///
    virtual gsl::not_null<process_list *> get_proclt() const
    { return m_proclt; }

    /// Get Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the domain associated with this vmcs
    ///
    virtual gsl::not_null<domain_intel_x64 *> get_domain() const
    { return m_domain; }

protected:

    void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                      gsl::not_null<vmcs_intel_x64_state *> guest_state) override;

private:

    coreid::type m_coreid;
    vcpuid::type m_vcpuid;
    gsl::not_null<process_list *> m_proclt;
    gsl::not_null<domain_intel_x64 *> m_domain;

public:

    friend class hyperkernel_ut;

    vmcs_intel_x64_hyperkernel(vmcs_intel_x64_hyperkernel &&) = default;
    vmcs_intel_x64_hyperkernel &operator=(vmcs_intel_x64_hyperkernel &&) = default;

    vmcs_intel_x64_hyperkernel(const vmcs_intel_x64_hyperkernel &) = delete;
    vmcs_intel_x64_hyperkernel &operator=(const vmcs_intel_x64_hyperkernel &) = delete;
};

#endif
