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

#ifndef PROCESS_H
#define PROCESS_H

#include <vector>
#include <memory>

#include <processid.h>
#include <processlistid.h>

#include <crt_info.h>
#include <bfelf_loader.h>

class process
{
public:

    process(int argc, const char **argv, processlistid::type procltid);
    ~process();

    gsl::not_null<bfelf_file_t *> load_elf(const std::string &filename);

private:

    processid::type m_id;
    processlistid::type m_procltid;

    uintptr_t m_info_addr;
    uintptr_t m_virt_addr;

    std::string m_filename;
    std::string m_basename;

    std::size_t m_argv_size;
    std::unique_ptr<char> m_argv;

    bfelf_loader_t m_loader;

    std::unique_ptr<char> m_stack;
    std::unique_ptr<crt_info> m_crt_info;

    std::vector<std::unique_ptr<char>> m_segments;
    std::vector<std::unique_ptr<bfelf_file_t>> m_elfs;

    void argv_size(int argc, const char **argv, std::size_t limit);
    void init_argv(int argc, const char **argv, uintptr_t vm_virt, std::size_t limit);

public:

    friend class hyperkernel_ut;

    process(process &&) = default;
    process &operator=(process &&) = default;

    process(const process &) = delete;
    process &operator=(const process &) = delete;
};

#endif
