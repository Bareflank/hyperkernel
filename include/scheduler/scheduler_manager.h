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

#ifndef SCHEDULER_MANAGER_H
#define SCHEDULER_MANAGER_H

#include <map>
#include <mutex>
#include <memory>

#include <user_data.h>
#include <schedulerid.h>

#include <scheduler/scheduler.h>
#include <scheduler/scheduler_factory.h>

class scheduler_manager
{
public:

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~scheduler_manager() = default;

    /// Get Singleton Instance
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// Get an instance to the singleton class.
    ///
    static scheduler_manager *instance() noexcept;

    /// Create Scheduler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param schedulerid the scheduler to initialize
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void create_scheduler(schedulerid::type schedulerid, user_data *data = nullptr);

    /// Delete Scheduler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param schedulerid the scheduler to delete
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_scheduler(schedulerid::type schedulerid, user_data *data = nullptr);

    /// Get Scheduler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param schedulerid the id of the scheduler to get
    /// @return returns the scheduler associated with the provided id
    ///
    virtual gsl::not_null<scheduler *> get_scheduler(schedulerid::type schedulerid);

    /// Add Task
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param schedulerid the id of the scheduler to add the task to
    /// @param tk the task to add
    ///
    virtual void add_task(schedulerid::type schedulerid, gsl::not_null<task *> tk);

    /// Remove Task
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param schedulerid the id of the scheduler to remove the task to
    /// @param tk the task to remove
    ///
    virtual void remove_task(schedulerid::type schedulerid, gsl::not_null<task *> tk);

    /// Yield
    ///
    /// Yields the current task and schedules the next one.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void yield(schedulerid::type schedulerid);

private:

    scheduler_manager() noexcept;
    std::unique_ptr<scheduler> &__add_scheduler(schedulerid::type schedulerid, user_data *data);
    std::unique_ptr<scheduler> &__get_scheduler(schedulerid::type schedulerid);

private:

    mutable std::mutex m_scheduler_mutex;
    std::map<schedulerid::type, std::unique_ptr<scheduler>> m_schedulers;

private:

    std::unique_ptr<scheduler_factory> m_scheduler_factory;

    void set_factory(std::unique_ptr<scheduler_factory> factory)
    { m_scheduler_factory = std::move(factory); }

public:

    friend class hyperkernel_ut;

    scheduler_manager(scheduler_manager &&) = default;
    scheduler_manager &operator=(scheduler_manager &&) = default;

    scheduler_manager(const scheduler_manager &) = delete;
    scheduler_manager &operator=(const scheduler_manager &) = delete;
};

/// Scheduler Manager Macro
///
/// The following macro can be used to quickly call the scheduler manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
/// @expects none
/// @ensures ret != nullptr
///
#define g_shm scheduler_manager::instance()

#endif
