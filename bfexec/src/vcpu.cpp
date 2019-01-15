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

#include <vcpu.h>
#include <debug.h>
#include <vmcall_hyperkernel_interface.h>

vcpu::vcpu(processlistid::type procltid) :
    m_id(vmcall__create_foreign_vcpu(procltid)),
    m_procltid(procltid)
{
    std::cout << "called vmcall__create_foreign_vcpu\n";
    if (m_id == vcpuid::invalid)
        throw std::runtime_error("vmcall__create_foreign_vcpu failed");
}

vcpu::~vcpu()
{
    if (!vmcall__delete_vcpu(m_id))
        bfwarning << "vmcall__delete_vcpu failed\n";
    std::cout << "called vmcall__delete_vcpu\n";
}
