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

#ifndef PROCESS_H
#define PROCESS_H

#include <map>
#include <list>
#include <mutex>
#include <memory>

#include <user_data.h>
#include <processid.h>

#include <thread/thread.h>
#include <thread/thread_factory.h>

class process : public user_data
{
public:

    using integer_pointer = uintptr_t;

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the process
    ///
    process(processid::type id);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~process() override = default;

    /// Init Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void init(user_data *data = nullptr);

    /// Fini Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void fini(user_data *data = nullptr);

    virtual void vm_map(uintptr_t virt,
                        uintptr_t phys,
                        uintptr_t size,
                        uintptr_t perm);

    virtual void vm_map_lookup(uintptr_t virt,
                               uintptr_t rtpt,
                               uintptr_t addr,
                               uintptr_t size,
                               uintptr_t perm);

    /// Process Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the process's id
    ///
    virtual processid::type id() const
    { return m_id; }

    /// Is Initialized
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the process is initialized, false otherwise.
    ///
    virtual bool is_initialized()
    { return m_is_initialized; }

    /// Create Thread
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual threadid::type create_thread(user_data *data = nullptr);

    /// Delete Thread
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param threadid the thread to delete
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_thread(threadid::type threadid, user_data *data = nullptr);

    /// Get Thread
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param threadid the id of the thread to get
    /// @return returns the thread associated with the provided id
    ///
    virtual gsl::not_null<thread *> get_thread(threadid::type threadid);

    /// Clear and Set Program Break
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param pb the new program break
    ///
    virtual void clear_set_program_break(integer_pointer pb);

    /// Increase Program Break (4k)
    ///
    /// Increases the program break for this process by 4k.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void increase_program_break_4k();

    /// Decrease Program Break (4k)
    ///
    /// Decrease the program break for this process by 4k.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void decrease_program_break_4k();

private:

    std::unique_ptr<thread> &__add_thread(threadid::type threadid, user_data *data);
    std::unique_ptr<thread> &__get_thread(threadid::type threadid);

private:

    processid::type m_id;
    bool m_is_initialized;

    integer_pointer m_program_break;
    std::list<std::unique_ptr<char[]>> m_pages;

private:

    mutable std::mutex m_thread_mutex;
    threadid::type m_thread_next_id;
    std::map<threadid::type, std::unique_ptr<thread>> m_threads;

private:

    std::unique_ptr<thread_factory> m_thread_factory;

    void set_factory(std::unique_ptr<thread_factory> factory)
    { m_thread_factory = std::move(factory); }

public:

    friend class hyperkernel_ut;

    process(process &&) = delete;
    process &operator=(process &&) = delete;

    process(const process &) = delete;
    process &operator=(const process &) = delete;
};

#endif
