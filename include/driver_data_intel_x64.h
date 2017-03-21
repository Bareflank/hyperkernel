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

#ifndef DRIVER_DATA_INTEL_X64_H
#define DRIVER_DATA_INTEL_X64_H

#include <user_data.h>

class domain_intel_x64;
class thread_intel_x64;
class process_list;

class driver_data_intel_x64 : public user_data
{
public:

    driver_data_intel_x64() noexcept :
        m_entry(0),
        m_domain(nullptr),
        m_thread(nullptr),
        m_proclt(nullptr)
    { }

    ~driver_data_intel_x64() override = default;

    uintptr_t m_entry;
    domain_intel_x64 *m_domain;
    thread_intel_x64 *m_thread;
    process_list *m_proclt;

public:

    driver_data_intel_x64(driver_data_intel_x64 &&) = default;
    driver_data_intel_x64 &operator=(driver_data_intel_x64 &&) = default;

    driver_data_intel_x64(const driver_data_intel_x64 &) = delete;
    driver_data_intel_x64 &operator=(const driver_data_intel_x64 &) = delete;
};

#endif
