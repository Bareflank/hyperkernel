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

#ifndef SCHEDULER_FACTORY_H
#define SCHEDULER_FACTORY_H

#include <memory>

#include <user_data.h>
#include <schedulerid.h>
#include <scheduler/scheduler.h>

class scheduler_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    scheduler_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~scheduler_factory() = default;

    /// Make Scheduler
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param schedulerid the schedulerid for the scheduler to create
    /// @param data user data passed to the scheduler
    /// @return returns a pointer to a newly created scheduler.
    ///
    virtual std::unique_ptr<scheduler> make_scheduler(schedulerid::type schedulerid, user_data *data = nullptr);
};

#endif
