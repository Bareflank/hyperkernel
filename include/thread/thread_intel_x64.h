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

#ifndef THREAD_INTEL_X64_H
#define THREAD_INTEL_X64_H

#include <thread/thread.h>
#include <exit_handler/state_save_intel_x64.h>

class thread_intel_x64 : public thread
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
    thread_intel_x64(threadid::type id, gsl::not_null<process *> proc);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~thread_intel_x64() override = default;

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
    void set_info(uintptr_t entry, uintptr_t stack, uintptr_t arg1, uintptr_t arg2) override;

    /// TODO:
    ///
    /// These should not be public
    ///
    uintptr_t m_stack;
    state_save_intel_x64 m_state_save;

public:

    friend class hyperkernel_ut;

    thread_intel_x64(thread_intel_x64 &&) = default;
    thread_intel_x64 &operator=(thread_intel_x64 &&) = default;

    thread_intel_x64(const thread_intel_x64 &) = delete;
    thread_intel_x64 &operator=(const thread_intel_x64 &) = delete;
};

#endif
