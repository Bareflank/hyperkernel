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

#ifndef PROCESS_LIST_MANAGER_H
#define PROCESS_LIST_MANAGER_H

#include <map>
#include <mutex>
#include <memory>

#include <user_data.h>
#include <processlistid.h>
#include <process_list/process_list_factory.h>

class process_list_manager
{
public:

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~process_list_manager() = default;

    /// Get Singleton Instance
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// Get an instance to the singleton class.
    ///
    static process_list_manager *instance() noexcept;

    /// Create Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    /// @return returns the id associated with the process list that was just
    ///     created
    ///
    virtual processlistid::type create_process_list(user_data *data = nullptr);

    /// Delete Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param processlistid the process_list to delete
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_process_list(processlistid::type processlistid, user_data *data = nullptr);

    /// Get Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param processlistid the id of the process list to get
    /// @return returns the process list associated with the provided id
    ///
    virtual gsl::not_null<process_list *> get_process_list(processlistid::type processlistid);

private:
    process_list_manager() noexcept;
    std::unique_ptr<process_list> &__add_process_list(processlistid::type processlistid, user_data *data);
    std::unique_ptr<process_list> &__get_process_list(processlistid::type processlistid);

private:

    mutable std::mutex m_process_list_mutex;
    processlistid::type m_process_list_next_id;
    std::map<processlistid::type, std::unique_ptr<process_list>> m_process_lists;

private:

    std::unique_ptr<process_list_factory> m_process_list_factory;

    void set_factory(std::unique_ptr<process_list_factory> factory)
    { m_process_list_factory = std::move(factory); }

public:

    friend class hyperkernel_ut;

    process_list_manager(process_list_manager &&) = default;
    process_list_manager &operator=(process_list_manager &&) = default;

    process_list_manager(const process_list_manager &) = delete;
    process_list_manager &operator=(const process_list_manager &) = delete;
};

/// Process List Manager Macro
///
/// The following macro can be used to quickly call the process_list manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
/// @expects none
/// @ensures ret != nullptr
///
#define g_plm process_list_manager::instance()

#endif
