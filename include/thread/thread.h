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

#include <gsl/gsl>

#include <memory>

#include <user_data.h>
#include <threadid.h>

class process;

class thread : public user_data
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the thread
    /// @param proc the process that owns this thread
    ///
    thread(threadid::type id, gsl::not_null<process *> proc);

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

    /// Set Thread Info
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param entry the entry point of the thread
    /// @param stack the thread's stack
    /// @param arg1 the first arg passed to the thread
    /// @param arg2 the second arg passed to the thread
    ///
    virtual void set_info(uintptr_t entry, uintptr_t stack, uintptr_t arg1, uintptr_t arg2) = 0;

    /// Thread Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the thread's process
    ///
    virtual gsl::not_null<process *> proc() const
    { return m_proc; }

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

private:

    threadid::type m_id;
    process *m_proc;

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
