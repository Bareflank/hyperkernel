//
// Bareflank Hypervisor Examples
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

#ifndef EXIT_HANDLER_INTEL_X64_HYPERKERNEL_H
#define EXIT_HANDLER_INTEL_X64_HYPERKERNEL_H

#include <gsl/gsl>

#include <exit_handler/exit_handler_intel_x64_eapis.h>

class exit_handler_intel_x64_hyperkernel : public exit_handler_intel_x64_eapis
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    exit_handler_intel_x64_hyperkernel();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~exit_handler_intel_x64_hyperkernel() override = default;

public:

    friend class hyperkernel_ut;

    exit_handler_intel_x64_hyperkernel(exit_handler_intel_x64_hyperkernel &&) = default;
    exit_handler_intel_x64_hyperkernel &operator=(exit_handler_intel_x64_hyperkernel &&) = default;

    exit_handler_intel_x64_hyperkernel(const exit_handler_intel_x64_hyperkernel &) = delete;
    exit_handler_intel_x64_hyperkernel &operator=(const exit_handler_intel_x64_hyperkernel &) = delete;
};

#endif
