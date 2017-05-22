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
#include <unistd.h>

#include <vector>
#include <memory>
#include <iostream>

#include <vcpu.h>
#include <process.h>
#include <process_list.h>
#include <vmcall_hyperkernel_interface.h>

using arg_list_type = std::vector<std::string>;

std::unique_ptr<process_list> g_proclt;
std::vector<std::unique_ptr<vcpu>> g_vcpus;
std::vector<std::unique_ptr<process>> g_processes;

extern "C" int set_affinity(long int core);

int
protected_main(int argc, const char **argv)
{
    long int core = strtol(argv[0], NULL, 0);
    if (core > 31 || core < 0) {
        throw std::invalid_argument("bfexec: need 0 <= core < 32");
    }

    auto ___ = gsl::finally([&]
    {
        g_processes.clear();
        g_vcpus.clear();
        g_proclt.reset();
    });

    if (set_affinity(core) != 0)
        throw std::runtime_error("failed to set cpu affinity");

    g_proclt = std::make_unique<process_list>();
    g_vcpus.push_back(std::make_unique<vcpu>(g_proclt->id()));
    g_processes.push_back(std::make_unique<process>(argc, &argv[1], g_proclt->id()));

    if (!vmcall__sched_yield())
        throw std::runtime_error("vmcall__sched_yield failed");

    return EXIT_SUCCESS;
}

void
terminate()
{
    std::cerr << "FATAL ERROR: terminate called" << '\n';
    abort();
}

void
new_handler()
{
    std::cerr << "FATAL ERROR: out of memory" << '\n';
    abort();
}

int
main(int argc, const char *argv[])
{
    std::set_terminate(terminate);
    std::set_new_handler(new_handler);

    if (argc < 3) {
        std::cerr << "bfexec: need argc >= 3\n";
        exit(22);
    }

    try
    {
        return protected_main(argc - 2, &argv[1]);
    }
    catch (std::exception &e)
    {
        std::cerr << "bfexec: caught unhandled exception" << '\n';
        std::cerr << "    - what() = " << e.what() << '\n';
    }
    catch (...)
    {
        std::cerr << "bfexec: caught unknown exception" << '\n';
    }

    return EXIT_FAILURE;
}
