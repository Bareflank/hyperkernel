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

#ifndef DOMAIN_H
#define DOMAIN_H

#include <gsl/gsl>

#include <map>
#include <mutex>
#include <memory>

#include <domainid.h>
#include <user_data.h>

class domain : public user_data
{
public:

    /// Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the domain
    ///
    domain(domainid::type id);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~domain() override = default;

    /// Init Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void init(user_data *data = nullptr);

    /// Fini Domain
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data user data that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    virtual void fini(user_data *data = nullptr);

    /// Domain Id
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the domain's id
    ///
    virtual domainid::type id() const
    { return m_id; }

    /// Is Initialized
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if the domain is initialized, false otherwise.
    ///
    virtual bool is_initialized()
    { return m_is_initialized; }

private:

    domainid::type m_id;
    bool m_is_initialized;

public:

    friend class hyperkernel_ut;

    domain(domain &&) = default;
    domain &operator=(domain &&) = default;

    domain(const domain &) = delete;
    domain &operator=(const domain &) = delete;
};

#endif
