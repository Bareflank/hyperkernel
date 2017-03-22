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

#ifndef DOMAIN_MANAGER_H
#define DOMAIN_MANAGER_H

#include <map>
#include <memory>

#include <domainid.h>
#include <user_data.h>
#include <domain/domain_factory.h>

class domain_manager
{
public:

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~domain_manager() = default;

    /// Get Singleton Instance
    ///
    /// @expects none
    /// @ensures ret != nullptr
    ///
    /// Get an instance to the singleton class.
    ///
    static domain_manager *instance() noexcept;

    /// Create Domain
    ///
    /// Creates the domain. Note that the domain is actually created by the
    /// domain factory's make_domain function.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual domainid::type create_domain(user_data *data = nullptr);

    /// Delete Domain
    ///
    /// Deletes the domain.
    ///
    /// @param domainid the domain to stop
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void delete_domain(domainid::type domainid, user_data *data = nullptr);

    /// Get Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param domainid the id of the domain to get
    /// @return returns the domain associated with the provided id
    ///
    virtual gsl::not_null<domain *> get_domain(domainid::type domainid);

private:

    domain_manager() noexcept;
    std::unique_ptr<domain> &__add_domain(domainid::type domainid, user_data *data);
    std::unique_ptr<domain> &__get_domain(domainid::type domainid);

private:

    mutable std::mutex m_domian_mutex;
    domainid::type m_domian_next_id;
    std::map<domainid::type, std::unique_ptr<domain>> m_domains;

private:

    std::unique_ptr<domain_factory> m_domain_factory;

    void set_factory(std::unique_ptr<domain_factory> factory)
    { m_domain_factory = std::move(factory); }

public:

    friend class hyperkernel_ut;

    domain_manager(domain_manager &&) = delete;
    domain_manager &operator=(domain_manager &&) = delete;

    domain_manager(const domain_manager &) = delete;
    domain_manager &operator=(const domain_manager &) = delete;
};

/// Domain Manager Macro
///
/// The following macro can be used to quickly call the domain manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
/// @expects none
/// @ensures ret != nullptr
///
#define g_dmm domain_manager::instance()

#endif
