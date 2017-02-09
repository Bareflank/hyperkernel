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

#ifndef PROCESS_LIST_FACTORY_H
#define PROCESS_LIST_FACTORY_H

#include <memory>

#include <user_data.h>
#include <processlistid.h>
#include <process_list/process_list.h>

class process_list_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    process_list_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~process_list_factory() = default;

    /// Make Task
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param processlistid the processlistid for the process_list to create
    /// @param data user data passed to the process_list
    /// @return returns a pointer to a newly created process_list.
    ///
    virtual std::unique_ptr<process_list> make_process_list(processlistid::type processlistid, user_data *data = nullptr);
};

#endif
