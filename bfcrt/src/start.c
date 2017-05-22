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

#include <stdlib.h>

#include <crt.h>
#include <crt_info.h>

#include <sys/syscall.h>

void *__dso_handle = 0;

int main(int argc, char *argv[]);

void
_start(struct crt_info *info)
{
    int i = 0;

    if (set_program_break(info->program_break) != 0)
        exit(1);

    for (i = 0; i < info->info_num; i++)
        local_init(&info->info[i]);

    // TODO: We need to pass argument information. Do to this, we will need
    // place the arguments into some allocated memory, and pass the string
    // information as well as the number of args.

    int ret = main(info->argc, info->argv);

    for (i = 0; i < info->info_num; i++)
        local_fini(&info->info[i]);

    exit(ret);
}
