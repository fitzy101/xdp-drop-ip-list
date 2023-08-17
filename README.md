# xdp-drop-ip-list

A program to drop packets sent to a particular IP address before they are
processed by the kernel TCP/IP stack. `xdp-drop-ip-list` utilises the eXpress
Data Path (XDP) and eBPF in Linux to process packets directly after the
interrupt processing of the network device driver.

By utilising eBPF and XPD we greatly reduce packet processing overhead and
require zero expensive data copies into user space.

## components

There are two parts to the packet processing: the kernel space and user space
programs (i.e. 'launcher').

The kernel component is an eBPF program attached to the XDP hook of a network
interface.

The launcher component handles the configuration of what addresses to drop
packets for and which interface to attach the program to (as well as the
boilerplate eBPF loading/attaching).

Communication from user to kernel space is via BPF map data types. User space
writes to target addresses to the map, kernel space reads the target addresses
from the map.

## reporting

Dropped packet counts are reported back to the user via stdout from the
user-space component. Nothing is printed if no packets have been dropped.

## dependencies

All required dependencies are available via contemporary package managers in
most Linux distributions.

- libbpf
- libbpf-devel
- libxdp
- libxdp-devel
- clang
- llvm
- Linux kernel 5.10+

# usage

The launcher requires 3 environment variables to be set in order to execute.
These are:

`XDP_DROP_ADDRESS_LIST_FILEPATH` - An absolute path to a file containing a list
of IP addresses (v4 and v6 are both supported). The list must be newline
delimited. If an address returns an error from `getaddrinfo(3)`, it is deemed
invalid and will be skipped. Currently, the maximum number of addresses
supported is 256 (this is likely to increase after more testing).

`XDP_DROP_INTERFACE_NAME` - The name of the network interface the program
should attach to. The launcher will validate that the interface exists and exit
with an error if it is invalid.

`XDP_DROP_PROGRAM_FILEPATH` - An absolute path to the `xdp-drop-kern.o` object
file, produced by running `make` or `make xdp-drop-kern.o` in the project
directory.

Example (must be executed as root):
```
$ sudo env \
    XDP_DROP_ADDRESS_LIST_FILEPATH="$(pwd)/addresses.list)" \
    XDP_DROP_INTERFACE_NAME=docker0 \
    XDP_DROP_PROGRAM_FILEPATH="$(pwd)/xdp-drop-kern.o" \
  xdp-drop-ip-list
```

## how it works

The launcher goes through the following sequence:
- load the kernel space XDP program from the BPF object file
- attach the program to the specified interface
- find the map named `targets` in the loaded program
- reads the list of addresses from the file at `XDP_DROP_ADDRESS_LIST_FILEPATH`
- valid addresses are set as keys in the `targets` map
- indefinitely loop through keys in the `dropped` map to print feedback to the
  user about number of dropped packets for each target

# performance

TODO(fitzy): add benchmark data. The intention is to complete the following
comparisons.

- no packet dropping (baseline)
- drop packets using the XDP program
- drop packets using an `iptables --table filter --jump DROP` rule
- drop packets using an haproxy `tcp-request connection reject` rule
