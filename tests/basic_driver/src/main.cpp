/*
 * Bareflank Hyperkernel
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <gsl/gsl>
#include <iostream>
#include <vmcall_hyperkernel_interface.h>

void
handle_ttys0(char val)
{
    vmcall__ttys1(val);
    vmcall__sched_yield();
}

int
main(int argc, const char *argv[])
{
    (void) argc;
    (void) argv;

    vmcall__register_ttys0(reinterpret_cast<uintptr_t>(handle_ttys0));

    auto msg = gsl::ensure_z("registered: ttys0\n");
    for (auto c : msg)
        vmcall__ttys1(c);

    vmcall__sched_yield_and_remove();
    return 0;
}
