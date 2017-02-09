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

#ifndef THREAD_FACTORY_H
#define THREAD_FACTORY_H

#include <gsl/gsl>

#include <memory>

#include <threadid.h>
#include <user_data.h>
#include <thread/thread.h>

class thread_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    thread_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~thread_factory() = default;

    /// Make Thread
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param threadid the threadid for the thread to create
    /// @param data user data passed to the thread
    /// @return returns a pointer to a newly created thread.
    ///
    virtual std::unique_ptr<thread> make_thread(threadid::type threadid, user_data *data = nullptr);
};

#endif
