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
#include <constants.h>
#include <upper_lower.h>

#include <process.h>
#include <vmcall_hyperkernel_interface.h>

#include <fstream>
#include <algorithm>

#include <sys/stat.h>
#include <unistd.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

using func_t = int (*)(int);

auto g_ld_library_path =
{
    "/home/user/hypervisor/sysroot_vmapp/x86_64-vmapp-elf/lib/"_s,
    "/home/user/hypervisor/sysroot_vmapp/x86_64-vmapp-elf/lib/cross/"_s
};

bool
exists(const std::string &name)
{
    struct stat buffer;
    return stat(name.c_str(), &buffer) == 0;
}

template<class T>
T *
malloc_aligned(std::size_t size)
{
    int ret = 0;
    void *ptr = nullptr;

    ret = posix_memalign(&ptr, 0x1000, size);
    (void) ret;

    return static_cast<T *>(memset(ptr, 0, size));
}

struct match_separator
{
    bool operator()(char ch) const
    { return ch == '/'; }
};

static std::string
basename(const std::string &filename)
{
    auto &&loc = std::find_if(filename.rbegin(), filename.rend(), match_separator());
    return std::string(loc.base(), filename.end());
}

static auto
read_binary(const std::string &filename)
{
    // TODO: We need to create a mmap file class that provides a char * span
    // for the memmap, and uses RAII to open, close the handle. This
    // implementation works for now, but performs needless copying.

    expects(!filename.empty());

    if (auto && handle = std::fstream(filename, std::ios_base::in | std::ios_base::binary))
        return std::vector<char>(std::istreambuf_iterator<char>(handle),
                                 std::istreambuf_iterator<char>());

    throw std::runtime_error("invalid file name: " + filename);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

process::process(const std::string &filename, processlistid::type procltid) :
    m_id(vmcall__create_foreign_process(procltid)),
    m_procltid(procltid),
    m_info_addr(0x00200000UL),
    m_virt_addr(0x00600000UL),
    m_filename(filename),
    m_basename(basename(filename))
{
    auto ret = 0L;

    if (m_id == processid::invalid)
        throw std::runtime_error("vmcall__create_process failed");

    memset(&m_loader, 0, sizeof(m_loader));

    auto &&elf = load_elf(m_filename);
    for (auto i = 0; i < bfelf_file_get_num_needed(elf); i++)
    {
        char *needed;
        ret = bfelf_file_get_needed(elf, static_cast<uint64_t>(i), &needed);
        if (ret != BFELF_SUCCESS)
            throw std::runtime_error("bfelf_file_get_needed failed");

        for (const auto &path : g_ld_library_path)
        {
            auto &&fullpath = path + needed;
            if (exists(fullpath))
            {
                load_elf(fullpath);
                break;
            }
        }
    }

    ret = bfelf_loader_relocate(&m_loader);
    if (ret != BFELF_SUCCESS)
        throw std::runtime_error("bfelf_loader_add failed");

    m_stack = std::unique_ptr<char>(malloc_aligned<char>(STACK_SIZE));
    auto &&stack_int = reinterpret_cast<uintptr_t>(m_stack.get());

    m_crt_info = std::unique_ptr<crt_info>(malloc_aligned<crt_info>(0x1000));
    auto &&crt_info_int = reinterpret_cast<uintptr_t>(m_crt_info.get());

    for (const auto &ef : m_elfs)
    {
        section_info_t info;

        ret = bfelf_file_get_section_info(ef.get(), &info);
        if (ret != BFELF_SUCCESS)
            throw std::runtime_error("bfelf_file_get_section_info failed");

        gsl::at(m_crt_info->info, m_crt_info->info_num++) = info;
    }

    m_crt_info->program_break = m_virt_addr;

    if (!vmcall__vm_map_foreign_lookup(
            m_procltid,
            m_id,
            0x00600000UL - STACK_SIZE,
            stack_int,
            STACK_SIZE,
            0))
        throw std::runtime_error("vmcall__vm_map_foreign_lookup failed");

    if (!vmcall__vm_map_foreign_lookup(
            m_procltid,
            m_id,
            m_info_addr,
            crt_info_int,
            0x1000,
            0))
        throw std::runtime_error("vmcall__vm_map_foreign_lookup failed");

    auto &&entry = 0UL;
    auto &&stack = 0x00600000UL - 0x1000;

    ret = bfelf_file_get_entry(elf, reinterpret_cast<void **>(&entry));
    if (ret != BFELF_SUCCESS)
        throw std::runtime_error("bfelf_file_get_entry failed");

    if (!vmcall__set_thread_foreign_info(
            m_procltid,
            m_id,
            0,
            entry,
            stack,
            m_info_addr,
            0))
        throw std::runtime_error("vmcall__set_thread_foreign_info failed");
}

process::~process()
{
    if (!vmcall__delete_foreign_process(m_procltid, m_id))
        bfwarning << "vmcall__delete_process failed\n";
}

gsl::not_null<bfelf_file_t *>
process::load_elf(const std::string &filename)
{
    auto &&ret = 0L;

    auto &&bin = read_binary(filename);
    auto &&elf = std::make_unique<bfelf_file_t>();
    auto &&elf_ptr = elf.get();

    ret = bfelf_file_init(bin.data(), bin.size(), elf_ptr);
    if (ret != BFELF_SUCCESS)
        throw std::runtime_error("bfelf_file_init failed");

    auto &&tsz = bfelf_file_get_total_size(elf_ptr);
    if (tsz < BFELF_SUCCESS)
        throw std::runtime_error("bfelf_file_get_total_size failed");

    if (bfn::lower(static_cast<uintptr_t>(tsz)) != 0)
        tsz = static_cast<std::ptrdiff_t>(bfn::upper(static_cast<uintptr_t>(tsz)) + 0x1000);

    auto &&pic = bfelf_file_get_pic_pie(elf_ptr);
    auto &&mem = malloc_aligned<char>(static_cast<std::size_t>(tsz));

    for (auto i = 0; i < bfelf_file_num_load_instrs(elf_ptr); i++)
    {
        struct bfelf_load_instr *instr = nullptr;

        ret = bfelf_file_get_load_instr(elf_ptr, static_cast<uint64_t>(i), &instr);
        if (ret != BFELF_SUCCESS)
            throw std::runtime_error("bfelf_file_get_load_instr failed");

        auto &&bin_view = gsl::span<char>(bin.data(), gsl::narrow_cast<std::ptrdiff_t>(bin.size()));
        auto &&mem_view = gsl::span<char>(mem, tsz);

        memcpy(&mem_view.at(instr->mem_offset), &bin_view.at(instr->file_offset), instr->filesz);

        auto &&virt_int = pic == 1 ? m_virt_addr + instr->mem_offset : instr->virt_addr;
        auto &&addr_int = reinterpret_cast<uintptr_t>(&mem_view.at(instr->mem_offset));
        auto &&perm_int = instr->perm;

        auto result = vmcall__vm_map_foreign_lookup(
                          m_procltid,
                          m_id,
                          virt_int,
                          addr_int,
                          instr->memsz,
                          perm_int);

        if (!result)
            throw std::runtime_error("vmcall__vm_map_foreign_lookup failed");
    }

    auto &&virt = pic == 1 ? reinterpret_cast<char *>(m_virt_addr) : nullptr;

    ret = bfelf_loader_add(&m_loader, elf_ptr, mem, virt);
    if (ret != BFELF_SUCCESS)
        throw std::runtime_error("bfelf_loader_add failed");

    m_elfs.push_back(std::move(elf));
    m_segments.push_back(std::unique_ptr<char>(mem));

    m_virt_addr += static_cast<uintptr_t>(tsz);
    if (bfn::lower(m_virt_addr) != 0)
        m_virt_addr = bfn::upper(m_virt_addr + 0x1000);

    return elf_ptr;
}
