#
# Bareflank Hyperkernel
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
# Subdirs
################################################################################

PARENT_SUBDIRS += bfc
PARENT_SUBDIRS += bfpthread
PARENT_SUBDIRS += bfsyscall
PARENT_SUBDIRS += bfcrt
PARENT_SUBDIRS += bfcxx
PARENT_SUBDIRS += bfexec
PARENT_SUBDIRS += src
PARENT_SUBDIRS += tests

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_subdir.mk
