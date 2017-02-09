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
#include <scheduler/scheduler_manager.h>

scheduler_manager *
scheduler_manager::instance() noexcept
{
    static scheduler_manager self;
    return &self;
}

void
scheduler_manager::create_scheduler(schedulerid::type schedulerid, user_data *data)
{
    auto ___ = gsl::on_failure([&]
    {
        std::lock_guard<std::mutex> guard(m_scheduler_mutex);
        m_schedulers.erase(schedulerid);
    });

    if (auto && schd = __add_scheduler(schedulerid, data))
        schd->init(data);
}

void
scheduler_manager::delete_scheduler(schedulerid::type schedulerid, user_data *data)
{
    auto ___ = gsl::finally([&]
    {
        std::lock_guard<std::mutex> guard(m_scheduler_mutex);
        m_schedulers.erase(schedulerid);
    });

    if (auto && schd = __get_scheduler(schedulerid))
        schd->fini(data);
}

gsl::not_null<scheduler *>
scheduler_manager::get_scheduler(schedulerid::type schedulerid)
{ return __get_scheduler(schedulerid).get(); }

void
scheduler_manager::add_task(schedulerid::type schedulerid, gsl::not_null<task *> tk)
{
    if (auto && schd = __get_scheduler(schedulerid))
        schd->add_task(tk);
    else
        throw std::runtime_error("invalid schedulerid: " + std::to_string(schedulerid));
}

void
scheduler_manager::remove_task(schedulerid::type schedulerid, gsl::not_null<task *> tk)
{
    if (auto && schd = __get_scheduler(schedulerid))
        schd->remove_task(tk);
    else
        throw std::runtime_error("invalid schedulerid: " + std::to_string(schedulerid));
}

void
scheduler_manager::yield(schedulerid::type schedulerid)
{
    if (auto && schd = __get_scheduler(schedulerid))
        schd->yield();
    else
        throw std::runtime_error("invalid schedulerid: " + std::to_string(schedulerid));
}

scheduler_manager::scheduler_manager() noexcept :
    m_scheduler_factory(std::make_unique<scheduler_factory>())
{ }

std::unique_ptr<scheduler> &
scheduler_manager::__add_scheduler(schedulerid::type schedulerid, user_data *data)
{
    if (!m_scheduler_factory)
        throw std::runtime_error("invalid scheduler factory");

    if (__get_scheduler(schedulerid))
        throw std::runtime_error("scheduler already exists: " + std::to_string(schedulerid));

    if (auto && schd = m_scheduler_factory->make_scheduler(schedulerid, data))
    {
        std::lock_guard<std::mutex> guard(m_scheduler_mutex);
        return m_schedulers[schedulerid] = std::move(schd);
    }

    throw std::runtime_error("make_scheduler returned a nullptr scheduler");
}

std::unique_ptr<scheduler> &
scheduler_manager::__get_scheduler(schedulerid::type schedulerid)
{
    std::lock_guard<std::mutex> guard(m_scheduler_mutex);
    return m_schedulers[schedulerid];
}
