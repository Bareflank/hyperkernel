<img src="https://raw.githubusercontent.com/Bareflank/hyperkernel/master/doc/images/bareflank_hyperkernel_logo.jpg" width="501">

[![GitHub version](https://badge.fury.io/gh/Bareflank%2Fextended_apis.svg)](https://badge.fury.io/gh/Bareflank%2Fextended_apis)
[![Build Status](https://travis-ci.org/Bareflank/hyperkernel.svg?branch=master)](https://travis-ci.org/Bareflank/hyperkernel)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor)'s main
goal is to provide the "bare" minimum hypervisor. Since Bareflank supports
C++ 11/14, multiple operating systems, and a full toolstack, it's not as
simple as say [SimpleVisor](https://github.com/ionescu007/SimpleVisor),
but still adheres to the same basic principles of leaving out the complexity
of a full blown hypervisor in favor of an implementation that is simple to
read and follow.

It is our goal to provide a hypervisor that others can extend to create
their own hypervisors. To this end, the purpose of this repository, is to
provide a set of APIs that enables the creation and management of guest
virtual machines. Because this set of APIs is designed to be generic, we
intended to support (over time) the following different guest virtual machine
types:

- VM applications (think [LibVMI](http://libvmi.com/) in a VM with no OS)
- Unikernels (e.g. [IncludeOS](http://www.includeos.org))
- PV Kernels (e.g. modified Linux kernel)
- Thick VMs (e.g. unmodified Windows, Linux, BSD, etc...)

## Compilation / Usage

To setup the hyperkernel, we must clone the extension into the Bareflank
root folder and run make (the following assumes this is running on Linux).

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor
git clone https://github.com/Bareflank/extended_apis.git
git clone https://github.com/Bareflank/hyperkernel.git

./tools/scripts/setup-<xxx>.sh --no-configure
sudo reboot

cd ~/hypervisor
./configure -m hyperkernel/bin/hyperkernel.modules

make driver_load

make
make quick
```

Currently, to test out the hyperkernel, you can run the following test
VM applications. The applications are basic C and C++ applications that
print "hello world" using either C or C++, and execute in a virtual machine
with no OS.

```
./makefiles/hyperkernel/bfexec/bin/native/bfexec /home/user/hypervisor/makefiles/hyperkernel/tests/basic_c/bin/cross/basic_c
./makefiles/hyperkernel/bfexec/bin/native/bfexec /home/user/hypervisor/makefiles/hyperkernel/tests/basic_cxx/bin/cross/basic_cxx
```

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Roadmap

The project roadmap can be located [here](https://github.com/Bareflank/hypervisor/projects)

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
