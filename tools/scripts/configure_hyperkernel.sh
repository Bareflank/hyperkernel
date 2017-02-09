#!/bin/bash -e
#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

cp -Rf $1/build_scripts/compiler_wrapper.sh $1/build_scripts/compiler_hyperkernel_wrapper.sh
cp -Rf `dirname $0`/compiler_wrapper_additions.sh /tmp/compiler_wrapper_additions.sh

perl -pe 's/# %CUSTOM_VARIABLES%\n/`cat \/tmp\/compiler_wrapper_additions.sh`/ge' -i $1/build_scripts/compiler_hyperkernel_wrapper.sh

rm -Rf /tmp/compiler_wrapper_additions.sh

rm -Rf $1/build_scripts/x86_64-vmapp-elf-ar
rm -Rf $1/build_scripts/x86_64-vmapp-elf-as
rm -Rf $1/build_scripts/x86_64-vmapp-elf-ld
rm -Rf $1/build_scripts/x86_64-vmapp-elf-nm
rm -Rf $1/build_scripts/x86_64-vmapp-elf-objcopy
rm -Rf $1/build_scripts/x86_64-vmapp-elf-objdump
rm -Rf $1/build_scripts/x86_64-vmapp-elf-ranlib
rm -Rf $1/build_scripts/x86_64-vmapp-elf-readelf
rm -Rf $1/build_scripts/x86_64-vmapp-elf-strip
rm -Rf $1/build_scripts/x86_64-vmapp-clang
rm -Rf $1/build_scripts/x86_64-vmapp-clang++
rm -Rf $1/build_scripts/x86_64-vmapp-nasm
rm -Rf $1/build_scripts/x86_64-vmapp-docker

ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-ar
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-as
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-ld
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-nm
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-objcopy
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-objdump
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-ranlib
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-readelf
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-elf-strip
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-clang
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-clang++
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-nasm
ln -s $1/build_scripts/compiler_hyperkernel_wrapper.sh $1/build_scripts/x86_64-vmapp-docker

mkdir -p $1/sysroot_vmapp/x86_64-vmapp-elf/lib/
cp -Rf $1/makefiles/bfunwind/bin/cross/libbfunwind.so $1/sysroot_vmapp/x86_64-vmapp-elf/lib/
