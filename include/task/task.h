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

#ifndef TASK_H
#define TASK_H

#include <gsl/gsl>

#include <coreid.h>
#include <vcpuid.h>

class domain;
class thread;
class process;
class process_list;

class task
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param coreid the id of the physical core that this task will execute on
    /// @param vcpuid the id of the vcpu that this task will execute on
    /// @param proclt the id of the process list that this task will execute on
    /// @param domain the domain that this task will execute on
    ///
    task(
        coreid::type coreid,
        vcpuid::type vcpuid,
        gsl::not_null<process_list *> proclt,
        gsl::not_null<domain *> domain);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~task();

    /// Schedule
    ///
    /// Executes this task. Note that the task is really a vCPU, which could
    /// be executing a bunch of VM apps, or a single Thick VM. For this reason,
    /// this is a pure virtual function as the vCPU needs to implement this
    /// function based on how the hardware executes a VM.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void schedule() = 0;

    /// Schedule (args)
    ///
    /// Executes this task. Note that the task is really a vCPU, which could
    /// be executing a bunch of VM apps, or a single Thick VM. For this reason,
    /// this is a pure virtual function as the vCPU needs to implement this
    /// function based on how the hardware executes a VM.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void schedule(thread *thrd, uintptr_t entry, uintptr_t arg1, uintptr_t arg2) = 0;

    /// Done
    ///
    /// @return returns true if there is no more work to be done,
    ///     false otherwise
    virtual size_t num_jobs();

private:

    coreid::type m_coreid;
    vcpuid::type m_vcpuid;
    gsl::not_null<process_list *> m_proclt;
    gsl::not_null<domain *> m_domain;

public:

    friend class hyperkernel_ut;

    task(task &&) = default;
    task &operator=(task &&) = default;

    task(const task &) = delete;
    task &operator=(const task &) = delete;
};

#endif
