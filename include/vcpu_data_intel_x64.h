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

#ifndef VCPU_DATA_INTEL_X64_H
#define VCPU_DATA_INTEL_X64_H

#include <gsl/gsl>

#include <coreid.h>
#include <user_data.h>

class process_list;
class domain_intel_x64;

class vcpu_data_intel_x64 : public user_data
{
public:

    vcpu_data_intel_x64() noexcept :
        m_is_host(false),
        m_coreid(0),
        m_proclt(nullptr),
        m_domain(nullptr)
    { }

    ~vcpu_data_intel_x64() override = default;

    bool m_is_host;
    coreid::type m_coreid;

    process_list *m_proclt;
    domain_intel_x64 *m_domain;

public:

    vcpu_data_intel_x64(vcpu_data_intel_x64 &&) = default;
    vcpu_data_intel_x64 &operator=(vcpu_data_intel_x64 &&) = default;

    vcpu_data_intel_x64(const vcpu_data_intel_x64 &) = delete;
    vcpu_data_intel_x64 &operator=(const vcpu_data_intel_x64 &) = delete;
};

#endif
