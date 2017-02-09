#
# Bareflank Unwind Library
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

################################################################################
# Target Information
################################################################################

TARGET_NAME:=bfcrt
TARGET_TYPE:=lib
TARGET_COMPILER:=cross

SYSROOT_NAME:=vmapp

################################################################################
# Compiler Flags
################################################################################

CROSS_CCFLAGS+=
CROSS_CXXFLAGS+=
CROSS_ASMFLAGS+=
CROSS_LDFLAGS+=
CROSS_ARFLAGS+=
CROSS_DEFINES+=

################################################################################
# Output
################################################################################

CROSS_OBJDIR+=%BUILD_REL%/.build
CROSS_OUTDIR+=%BUILD_ABS%/sysroot_vmapp/x86_64-vmapp-elf/lib/

POST_COMMAND:=if [[ -d %BUILD_ABS%/sysroot_vmapp/x86_64-vmapp-elf/lib/ ]]; then cp -Rf %BUILD_ABS%/makefiles/bfunwind/bin/cross/libbfunwind.so %BUILD_ABS%/sysroot_vmapp/x86_64-vmapp-elf/lib/; fi

################################################################################
# Sources
################################################################################

SOURCES+=start.c

INCLUDE_PATHS+=%HYPER_ABS%/include/

INCLUDE_PATHS+=../../include/
INCLUDE_PATHS+=%HYPER_ABS%/bfelf_loader/include/

LIBS+=

LIBRARY_PATHS+=

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_target.mk
