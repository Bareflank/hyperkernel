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

#include <process/process.h>
#include <memory_manager/memory_manager_x64.h>

process::process(processid::type id) :
    m_id(id),
    m_is_initialized(false),
    m_program_break(0),
    m_thread_next_id(0),
    m_thread_factory(std::make_unique<thread_factory>())
{
    if ((id & processid::reserved) != 0)
        throw std::invalid_argument("invalid processid: " + std::to_string(id));
}

void
process::init(user_data *data)
{
    this->create_thread();

    (void) data;
    m_is_initialized = true;
}

void
process::fini(user_data *data)
{
    (void) data;
    m_is_initialized = false;
}

void
process::vm_map(uintptr_t virt,
                uintptr_t phys,
                uintptr_t size,
                uintptr_t perm)
{
    (void) virt;
    (void) phys;
    (void) size;
    (void) perm;

    throw std::logic_error("vm_map not implemented!!!");
}

void
process::vm_map_lookup(uintptr_t virt,
                       uintptr_t rtpt,
                       uintptr_t addr,
                       uintptr_t size,
                       uintptr_t perm)
{
    (void) virt;
    (void) rtpt;
    (void) addr;
    (void) size;
    (void) perm;

    throw std::logic_error("vm_map not implemented!!!");
}

threadid::type
process::create_thread(user_data *data)
{
    auto ___ = gsl::on_failure([&]
    {
        std::lock_guard<std::mutex> guard(m_thread_mutex);
        m_threads.erase(m_thread_next_id);
    });

    if (auto && thread = __add_thread(m_thread_next_id, data))
        thread->init(data);

    return m_thread_next_id++;
}

void
process::delete_thread(threadid::type threadid, user_data *data)
{
    auto ___ = gsl::finally([&]
    {
        std::lock_guard<std::mutex> guard(m_thread_mutex);
        m_threads.erase(threadid);
    });

    if (auto && thread = __get_thread(threadid))
        thread->fini(data);
}

gsl::not_null<thread *>
process::get_thread(threadid::type threadid)
{ return __get_thread(threadid).get(); }

void
process::clear_set_program_break(integer_pointer pb)
{
    m_program_break = pb;
    m_pages.clear();
}

void
process::increase_program_break_4k()
{
    auto &&page = std::make_unique<char[]>(4096);

    auto &&virt = m_program_break;
    auto &&phys = g_mm->virtptr_to_physint(page.get());

    // TODO:
    //
    // We need to use permissions here. Note that the permissions need to
    // be generalized (probably use the permissions for mmap)
    //

    this->vm_map(virt, phys, 0x1000, 0);

    m_program_break += 0x1000;
    m_pages.push_back(std::move(page));
}

void
process::decrease_program_break_4k()
{
    m_program_break -= 0x1000;
    m_pages.pop_back();
}

std::unique_ptr<thread> &
process::__add_thread(threadid::type threadid, user_data *data)
{
    if (!m_thread_factory)
        throw std::runtime_error("invalid thread factory");

    if (__get_thread(threadid))
        throw std::runtime_error("thread already exists: " + std::to_string(threadid));

    if (auto && thread = m_thread_factory->make_thread(threadid, data))
    {
        std::lock_guard<std::mutex> guard(m_thread_mutex);
        return m_threads[threadid] = std::move(thread);
    }

    throw std::runtime_error("make_thread returned a nullptr thread");
}

std::unique_ptr<thread> &
process::__get_thread(threadid::type threadid)
{
    std::lock_guard<std::mutex> guard(m_thread_mutex);
    return m_threads[threadid];
}
