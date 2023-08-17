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

## building

To compile the launcher and BPF object, run `make` in the root of the
repository. If the output looks like this, you have all dependencies installed:

```
$ make
clang -O2 -Wall -g -target bpf -c xdp-drop-kern.c -o xdp-drop-kern.o
clang -O2 -Wall xdp-drop-launcher.c -o xdp-drop-ip-list -lbpf -lxdp
chmod +x xdp-drop-ip-list
```

## executing

The below is an example run. We will create a list of IP addresses to block,
execute the launcher, and poll for dropped packet counts.

```bash
$ cat <<EOF > addresses.list
172.17.0.3
2404:bf40:c202:d:0:242:ac11:2
2404:bf40:c202:d:0:242:ac11:3
EOF
$ sudo env \
    XDP_DROP_ADDRESS_LIST_FILEPATH="$(pwd)/addresses.list" \
    XDP_DROP_INTERFACE_NAME=docker0 \
    XDP_DROP_PROGRAM_FILEPATH="$(pwd)/xdp-drop-kern.o"
  xdp-drop-ip-list
blocking address: 172.17.0.3
blocking address: 2404:bf40:c202:d:0:242:ac11:2
blocking address: 2404:bf40:c202:d:0:242:ac11:3
```

In another terminal, ping an address accessible over the specifed interface.
You will see the dropped packet count increasing now there is something to
report on.

```
$ sudo env \
    XDP_DROP_ADDRESS_LIST_FILEPATH="$(pwd)/addresses.list" \
    XDP_DROP_INTERFACE_NAME=docker0 \
    XDP_DROP_PROGRAM_FILEPATH="$(pwd)/xdp-drop-kern.o"
  xdp-drop-ip-list
blocking address: 172.17.0.3
blocking address: 2404:bf40:c202:d:0:242:ac11:2
blocking address: 2404:bf40:c202:d:0:242:ac11:3
total dropped for 172.17.0.3: 24
total dropped for 172.17.0.3: 24
total dropped for 172.17.0.3: 24
total dropped for 172.17.0.3: 24
total dropped for 2404:bf40:c202:d:0:242:ac11:2: 2
total dropped for 172.17.0.3: 24
total dropped for 2404:bf40:c202:d:0:242:ac11:2: 3
total dropped for 172.17.0.3: 24
total dropped for 2404:bf40:c202:d:0:242:ac11:2: 5
total dropped for 172.17.0.3: 24
total dropped for 2404:bf40:c202:d:0:242:ac11:2: 7
...
```

Hit ^C or send SIGTERM to the running process to shutdown gracefully and detach
any BPF programs from the specified interface.
```
total dropped for 2404:bf40:c202:d:0:242:ac11:2: 11
^CDetached XDP program
```

That's it!

# performance

TODO(fitzy): add benchmark data. The intention is to complete the following
comparisons.

- no packet dropping (baseline)
- drop packets using the XDP program
- drop packets using an `iptables --table filter --jump DROP` rule
- drop packets using an haproxy `tcp-request connection reject` rule

# TODO(fitzy)

There are still many sharp edges to this prototype.

- ensure BPF programs are detached from any interfaces on program exit (where we
don't already)
- add SIGHUP handler to reload addresses into BPF map from file, to enable runtime
changes to target list
