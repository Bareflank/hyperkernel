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
#include <exception.h>

#include <vcpu/vcpu_manager.h>
#include <process_list/process_list.h>

process_list::process_list(
    processlistid::type id,
    gsl::not_null<domain *> domain) :

    m_id(id),
    m_domain(domain),
    m_is_initialized(false),
    m_process_next_id(0),
    m_process_factory(std::make_unique<process_factory>())
{
    if ((id & processlistid::reserved) != 0)
        throw std::invalid_argument("invalid processlistid");
}

process_list::~process_list()
{
    for (auto vcpuid : m_vcpuids)
        g_vcm->delete_vcpu(vcpuid);
}

void
process_list::init(user_data *data)
{
    (void) data;

    m_is_initialized = true;
}

void
process_list::fini(user_data *data)
{
    (void) data;

    m_is_initialized = false;
}

void
process_list::add_vcpu(vcpuid::type id)
{
    std::lock_guard<std::mutex> guard(m_vcpu_mutex);
    m_vcpuids.insert(id);
}

void
process_list::remove_vcpu(vcpuid::type id)
{
    // FUTURE:
    //
    // We need a way to cleanup the process list if the number of vcpus goes
    // to zero. This is because if the controlling process dies, or forgets
    // to remove the process list, the kernel will leak this resource.
    //

    std::lock_guard<std::mutex> guard(m_vcpu_mutex);
    m_vcpuids.erase(id);
}

std::size_t
process_list::vcpu_count() const
{ return m_vcpuids.size(); }

processid::type
process_list::create_process(user_data *data)
{
    auto ___ = gsl::on_failure([&]
    {
        std::lock_guard<std::mutex> guard(m_process_mutex);
        m_processes.erase(m_process_next_id);
    });

    if (auto && process = __add_process(m_process_next_id, data))
        process->init(data);

    return m_process_next_id++;
}

void
process_list::delete_process(processid::type processid, user_data *data)
{
    auto ___ = gsl::finally([&]
    {
        std::lock_guard<std::mutex> guard(m_process_mutex);
        m_processes.erase(processid);
    });

    if (auto && process = __get_process(processid))
        process->fini(data);
}

gsl::not_null<process *>
process_list::get_process(processid::type processid)
{ return __get_process(processid).get(); }

std::pair<thread *, process *>
process_list::next_job()
{
    if (m_processes.empty())
        return {};

    auto && proc = m_processes.begin()->second.get();
    auto && thrd = proc->get_thread(0);

    return {thrd, proc};
}

std::unique_ptr<process> &
process_list::__add_process(processid::type processid, user_data *data)
{
    if (!m_process_factory)
        throw std::runtime_error("invalid process factory");

    if (__get_process(processid))
        throw std::runtime_error("process already exists: " + std::to_string(processid));

    if (auto && process = m_process_factory->make_process(processid, data))
    {
        std::lock_guard<std::mutex> guard(m_process_mutex);
        return m_processes[processid] = std::move(process);
    }

    throw std::runtime_error("make_process returned a nullptr process");
}

std::unique_ptr<process> &
process_list::__get_process(processid::type processid)
{
    std::lock_guard<std::mutex> guard(m_process_mutex);
    return m_processes[processid];
}
