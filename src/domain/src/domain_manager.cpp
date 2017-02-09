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

#include <gsl/gsl>

#include <debug.h>
#include <domain/domain_manager.h>

domain_manager *
domain_manager::instance() noexcept
{
    static domain_manager self;
    return &self;
}

domainid::type
domain_manager::create_domain(user_data *data)
{
    auto ___ = gsl::on_failure([&]
    {
        std::lock_guard<std::mutex> guard(m_domian_mutex);
        m_domains.erase(m_domian_next_id);
    });

    if (auto && domain = __add_domain(m_domian_next_id, data))
        domain->init(data);

    return m_domian_next_id++;
}

void
domain_manager::delete_domain(domainid::type domainid, user_data *data)
{
    auto ___ = gsl::finally([&]
    {
        std::lock_guard<std::mutex> guard(m_domian_mutex);
        m_domains.erase(domainid);
    });

    if (auto && domain = __get_domain(domainid))
        domain->fini(data);
}

gsl::not_null<domain *>
domain_manager::get_domain(domainid::type domainid)
{ return __get_domain(domainid).get(); }

domain_manager::domain_manager() noexcept :
    m_domian_next_id(0),
    m_domain_factory(std::make_unique<domain_factory>())
{ }

std::unique_ptr<domain> &
domain_manager::__add_domain(domainid::type domainid, user_data *data)
{
    if (!m_domain_factory)
        throw std::runtime_error("invalid domain factory");

    if (__get_domain(domainid))
        throw std::runtime_error("domain already exists: " + std::to_string(domainid));

    if (auto && domain = m_domain_factory->make_domain(domainid, data))
    {
        std::lock_guard<std::mutex> guard(m_domian_mutex);
        return m_domains[domainid] = std::move(domain);
    }

    throw std::runtime_error("make_domain returned a nullptr domain");
}

std::unique_ptr<domain> &
domain_manager::__get_domain(domainid::type domainid)
{
    std::lock_guard<std::mutex> guard(m_domian_mutex);
    return m_domains[domainid];
}
