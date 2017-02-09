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

#ifndef PROCESS_LIST_H
#define PROCESS_LIST_H

#include <gsl/gsl>

#include <map>
#include <set>
#include <mutex>
#include <memory>

#include <vcpuid.h>
#include <user_data.h>
#include <processlistid.h>

#include <process/process.h>
#include <process/process_factory.h>

class domain;
class thread;
class process;

class process_list : public user_data
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the process_list
    /// @param domain the domain the process_list belongs too
    ///
    process_list(
        processlistid::type id,
        gsl::not_null<domain *> domain);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~process_list() override;

    /// Init Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void init(user_data *data = nullptr);

    /// Fini Process List
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void fini(user_data *data = nullptr);

    /// Process List Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the process list's id
    ///
    virtual processlistid::type id() const
    { return m_id; }

    /// Get Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the domain associated with this process list
    ///
    virtual gsl::not_null<domain *> get_domain() const
    { return m_domain; }

    /// Is Initialized
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the process list is initialized, false otherwise.
    ///
    virtual bool is_initialized()
    { return m_is_initialized; }

    /// Add vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the vcpu id to add to the process list
    ///
    virtual void add_vcpu(vcpuid::type id);

    /// Remove vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the vcpu id to add to the process list
    ///
    virtual void remove_vcpu(vcpuid::type id);

    /// vCPU Count
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the number of vcpus this process list has
    ///
    virtual std::size_t vcpu_count() const;

    /// Create Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual processid::type create_process(user_data *data = nullptr);

    /// Delete Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param processid the process to delete
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_process(processid::type processid, user_data *data = nullptr);

    /// Get Process
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param processid the id of the process to get
    /// @return returns the process associated with the provided id
    ///
    virtual gsl::not_null<process *> get_process(processid::type processid);

    /// Get Next Job
    ///
    /// This function is called by a vCPU to get the next thing to execute.
    /// The vCPU will need both the process and the thread in order to setup
    /// the vCPU for execution.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a thread (and it's parent process) to be executed
    ///     by a vCPU
    ///
    virtual std::pair<thread *, process *> next_job();

private:

    std::unique_ptr<process> &__add_process(processid::type processid, user_data *data);
    std::unique_ptr<process> &__get_process(processid::type processid);

private:

    processlistid::type m_id;
    gsl::not_null<domain *> m_domain;

    bool m_is_initialized;

private:

    mutable std::mutex m_vcpu_mutex;
    std::set<vcpuid::type> m_vcpuids;

private:

    mutable std::mutex m_process_mutex;
    processid::type m_process_next_id;
    std::map<processid::type, std::unique_ptr<process>> m_processes;

private:

    std::unique_ptr<process_factory> m_process_factory;

    void set_factory(std::unique_ptr<process_factory> factory)
    { m_process_factory = std::move(factory); }

public:

    friend class hyperkernel_ut;

    process_list(process_list &&) = default;
    process_list &operator=(process_list &&) = default;

    process_list(const process_list &) = delete;
    process_list &operator=(const process_list &) = delete;
};

#endif
