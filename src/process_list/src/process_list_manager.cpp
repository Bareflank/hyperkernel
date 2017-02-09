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

#include <gsl/gsl>

#include <debug.h>
#include <vcpuid.h>
#include <process_list/process_list_manager.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

process_list_manager *
process_list_manager::instance() noexcept
{
    static process_list_manager self;
    return &self;
}

processlistid::type
process_list_manager::create_process_list(user_data *data)
{
    auto ___ = gsl::on_failure([&]
    {
        std::lock_guard<std::mutex> guard(m_process_list_mutex);
        m_process_lists.erase(m_process_list_next_id);
    });

    if (auto && process_list = __add_process_list(m_process_list_next_id, data))
        process_list->init(data);

    return m_process_list_next_id++;
}

void
process_list_manager::delete_process_list(processlistid::type processlistid, user_data *data)
{
    auto ___ = gsl::finally([&]
    {
        std::lock_guard<std::mutex> guard(m_process_list_mutex);
        m_process_lists.erase(processlistid);
    });

    if (auto && process_list = __get_process_list(processlistid))
        process_list->fini(data);
}

gsl::not_null<process_list *>
process_list_manager::get_process_list(processlistid::type processlistid)
{ return __get_process_list(processlistid).get(); }

process_list_manager::process_list_manager() noexcept :
    m_process_list_next_id(0),
    m_process_list_factory(std::make_unique<process_list_factory>())
{ }

std::unique_ptr<process_list> &
process_list_manager::__add_process_list(processlistid::type processlistid, user_data *data)
{
    if (!m_process_list_factory)
        throw std::runtime_error("invalid process_list factory");

    if (__get_process_list(processlistid))
        throw std::runtime_error("process_list already exists: " + std::to_string(processlistid));

    if (auto && process_list = m_process_list_factory->make_process_list(processlistid, data))
    {
        std::lock_guard<std::mutex> guard(m_process_list_mutex);
        return m_process_lists[processlistid] = std::move(process_list);
    }

    throw std::runtime_error("make_process_list returned a nullptr process_list");
}

std::unique_ptr<process_list> &
process_list_manager::__get_process_list(processlistid::type processlistid)
{
    std::lock_guard<std::mutex> guard(m_process_list_mutex);
    return m_process_lists[processlistid];
}
