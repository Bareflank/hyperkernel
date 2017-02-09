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

#include <debug.h>
#include <thread/thread.h>

thread::thread(threadid::type id) :
    m_id(id),
    m_is_running(false),
    m_is_initialized(false)
{
    if ((id & threadid::reserved) != 0)
        throw std::invalid_argument("invalid threadid");
}

void
thread::init(user_data *data)
{
    (void) data;

    m_is_initialized = true;
}

void
thread::fini(user_data *data)
{
    (void) data;

    if (m_is_running)
        this->hlt();

    m_is_initialized = false;
}

void
thread::run(user_data *data)
{
    (void) data;

    m_is_running = true;
}

void
thread::hlt(user_data *data)
{
    (void) data;

    m_is_running = false;
}

void
thread::set_info(uintptr_t entry,
                 uintptr_t stack,
                 uintptr_t arg1,
                 uintptr_t arg2)
{
    m_entry = entry;
    m_stack = stack;
    m_arg1 = arg1;
    m_arg2 = arg2;

    // bfdebug << "[thread #" << id() << "]: setting info\n";
    // bfdebug << "  - entry: " << view_as_pointer(m_entry) << '\n';
    // bfdebug << "  - stack: " << view_as_pointer(m_stack) << '\n';
    // bfdebug << "  - arg1: " << view_as_pointer(m_arg1) << '\n';
    // bfdebug << "  - arg2: " << view_as_pointer(m_arg2) << '\n';
}
