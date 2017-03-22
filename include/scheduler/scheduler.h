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

#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <gsl/gsl>

#include <list>

#include <user_data.h>
#include <schedulerid.h>

#include <task/task.h>

class scheduler : public user_data
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    scheduler(schedulerid::type id);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~scheduler() override = default;

    /// Init Scheduler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void init(user_data *data = nullptr);

    /// Fini Scheduler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void fini(user_data *data = nullptr);

    /// Scheduler Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the scheduler's id
    ///
    virtual schedulerid::type id() const
    { return m_id; }

    /// Add Task
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param tk the task to add to the scheduler
    ///
    virtual void add_task(gsl::not_null<task *> tk);

    /// Remove Task
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param tk the task to remove from the scheduler
    ///
    virtual void remove_task(gsl::not_null<task *> tk);

    /// Yield
    ///
    /// Yields the current task and schedules the next one.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void yield();

    /// Yield
    ///
    /// Yields the current task and schedules the next one.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void schedule(thread *thrd, uintptr_t entry, uintptr_t arg1, uintptr_t arg2);

private:

    schedulerid::type m_id;
    std::list<task *> m_tasks;

public:

    friend class hyperkernel_ut;

    scheduler(scheduler &&) = default;
    scheduler &operator=(scheduler &&) = default;

    scheduler(const scheduler &) = delete;
    scheduler &operator=(const scheduler &) = delete;
};

#endif
