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

#ifndef THREAD_H
#define THREAD_H

#include <memory>

#include <user_data.h>
#include <threadid.h>

class thread : public user_data
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the thread
    ///
    thread(threadid::type id);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~thread() override = default;

    /// Init thread
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void init(user_data *data = nullptr);

    /// Fini thread
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void fini(user_data *data = nullptr);

    /// Run
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void run(user_data *data = nullptr);

    /// Halt
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void hlt(user_data *data = nullptr);

    void set_info(uintptr_t entry,
                  uintptr_t stack,
                  uintptr_t arg1,
                  uintptr_t arg2);

    /// Thread Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the thread's id
    ///
    virtual threadid::type id() const
    { return m_id; }

    /// Is Running
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the thread is running, false otherwise.
    ///
    virtual bool is_running()
    { return m_is_running; }

    /// Is Initialized
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the thread is initialized, false otherwise.
    ///
    virtual bool is_initialized()
    { return m_is_initialized; }

    virtual uintptr_t entry() const
    { return m_entry; }

    virtual uintptr_t stack() const
    { return m_stack; }

    virtual uintptr_t arg1() const
    { return m_arg1; }

    virtual uintptr_t arg2() const
    { return m_arg2; }

private:

    threadid::type m_id;

    uintptr_t m_entry;
    uintptr_t m_stack;
    uintptr_t m_arg1;
    uintptr_t m_arg2;

    bool m_is_running;
    bool m_is_initialized;

public:

    friend class hyperkernel_ut;

    thread(thread &&) = default;
    thread &operator=(thread &&) = default;

    thread(const thread &) = delete;
    thread &operator=(const thread &) = delete;
};

#endif
