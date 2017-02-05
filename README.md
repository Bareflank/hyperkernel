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
their own hypervisors. To this end, it is likely that when creating your
own hypervisor, some tasks will be redundant. For example, starting and
stopping guest virtual machines, setting up guest -> guest communications,
and managing vmcall permissions will likely all be needed if your particular
use case requires guest virtual machine support.

The purpose of this repository, is to provide a set of APIs that enables the
creation and management of guest virtual machines. Because this set of APIs
is designed to be generic, we intended to support (over time) the following
different guest virtual machine types:

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
./configure -m ./hyperkernel/bin/hyperkernel.modules

make
make test
```

To test out the extended version of Bareflank, all we need to do is run the
make shortcuts as usual:

```
make driver_load
make quick

make status
make dump

make stop
make driver_unload
```

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Roadmap

The project roadmap can be located [here](https://github.com/Bareflank/hypervisor/projects)

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
