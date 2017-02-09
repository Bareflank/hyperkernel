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

#include <vcpuid.h>
#include <process_list_data.h>
#include <vcpu_data_intel_x64.h>

#include <domain/domain_manager.h>
#include <domain/domain_intel_x64.h>

#include <scheduler/scheduler_manager.h>
#include <process_list/process_list_manager.h>

static process_list_data g_pld;
static vcpu_data_intel_x64 g_vd;

user_data *
pre_create_vcpu(vcpuid::type id)
{
    static auto initialized = false;

    g_shm->create_scheduler(id);

    if (!initialized)
    {
        auto &&domainid = g_dmm->create_domain();
        g_pld.m_domain = g_dmm->get_domain(domainid).get();

        auto &&procltid = g_plm->create_process_list(&g_pld);
        g_vd.m_proclt = g_plm->get_process_list(procltid).get();
        g_vd.m_domain = dynamic_cast<domain_intel_x64 *>(g_dmm->get_domain(domainid).get());

        initialized = true;
    }

    g_vd.m_coreid = id;
    g_vd.m_is_host = true;

    return &g_vd;
}
