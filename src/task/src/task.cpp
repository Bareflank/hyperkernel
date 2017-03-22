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

#include <task/task.h>
#include <process_list/process_list.h>
#include <scheduler/scheduler_manager.h>

task::task(
    coreid::type coreid,
    vcpuid::type vcpuid,
    gsl::not_null<process_list *> proclt,
    gsl::not_null<domain *> domain) :

    m_coreid(coreid),
    m_vcpuid(vcpuid),
    m_proclt(proclt),
    m_domain(domain)
{
    // TODO:
    //
    // Get rid of the need to talk to the scheduler manager. To do this, we
    // will need to be given the scheduler for this task.
    //

    g_shm->add_task(m_coreid, this);
    m_proclt->add_vcpu(m_vcpuid);
}

task::~task()
{
    // TODO:
    //
    // Get rid of the need to talk to the scheduler manager. To do this, we
    // will need to be given the scheduler for this task.
    //

    m_proclt->remove_vcpu(m_vcpuid);
    g_shm->remove_task(m_coreid, this);
}

size_t task::num_jobs()
{ return m_proclt->num_jobs(); }
