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

#ifndef DOMAIN_FACTORY_H
#define DOMAIN_FACTORY_H

#include <memory>

#include <domainid.h>
#include <user_data.h>
#include <domain/domain.h>

class domain_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    domain_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~domain_factory() = default;

    /// Make Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param domainid the domainid for the domain to create
    /// @param data user data passed to the domain
    /// @return returns a pointer to a newly created domain.
    ///
    virtual std::unique_ptr<domain> make_domain(domainid::type domainid, user_data *data = nullptr);

public:

    domain_factory(domain_factory &&) = default;
    domain_factory &operator=(domain_factory &&) = default;

    domain_factory(const domain_factory &) = delete;
    domain_factory &operator=(const domain_factory &) = delete;
};

#endif
