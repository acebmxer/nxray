# Traffic per VLAN and per device

[← back to the README](../README.md)

The switch measures traffic **per port**: `show interface` gives each port's
in and out rate, averaged over 30 seconds, and its byte and packet counters.
It does not say which VLAN or which device that traffic belongs to. NXray
works out two estimates from the port figures it already reads, without
asking the switch for anything more or changing it. Both are always labelled
as estimates, and this page says what each one leaves out.

## Per device

**Where:** the **Busiest devices** card and the **Traffic now** column of
the MAC address table on the Neighbors page, the **Connected devices** card
on a port's page, and the side panel of a port on the Ports page.

**What it is:** a device that is **alone on an access port** gets that
port's traffic as its own. An access port carries one VLAN, so when the MAC
address table has a single address on it, all the port's traffic is that
device's. The figures are named from the device's
side:

- **Sends** is what came in on the port (the port's *in* rate).
- **Receives** is what went out of it (the port's *out* rate).

Busiest devices lists up to 10 devices with the most traffic in both
directions together; idle ones are left out. A device's traffic over time is
its port's traffic chart, for as long as the device has been on that port.

**What it leaves out:** a device gets no figure when

- its port is a **trunk** (it carries several VLANs);
- its port is part of a **port-channel** (the switch learns addresses on the
  port-channel, not on its ports);
- **several addresses** are learned on its port: another switch, a hypervisor
  with virtual machines, or a phone with a computer behind it. The switch
  counts the port as a whole, so the traffic cannot be split between them;
- its port is down.

A port's page says which of these applies when nobody on it gets a figure.

The Neighbors page reads `show interface` once more for this, in its own
request. If the switch refuses it, the page shows no figures and everything
else as before.

## Per VLAN

**Where:** the **Traffic now** column of the VLANs page, and the **Traffic
per VLAN** charts on the History page (one for what the VLAN's devices sent,
one for what was sent to them).

**What it is:** each VLAN's **access ports that are up, added up**. History
reads `show interface status` with each sample, which names each access
port's VLAN, and stores the sum for each VLAN that has an access port up.
The VLANs page shows the newest sample, as long as it is no older than three
history intervals; the History page draws up to eight VLANs, the busiest in
the range, in the same colours on both charts, and says how many quieter
ones it left out.

**What it leaves out:**

- **Trunks.** A trunk carries several VLANs, and its counters cannot be
  split by VLAN, so traffic that reaches a VLAN over a trunk (from another
  switch, a hypervisor, a firewall) is missing.
- **Routed ports**, which are in no VLAN.
- Everything, when history is off (`NXRAY_HISTORY_INTERVAL=0`): the VLANs
  page then shows no traffic.

Traffic between two access ports of the same VLAN is counted on both: once
as sent (in on one port) and once as received (out on the other). Traffic a
device sends to its gateway through a VLAN interface on this switch is
counted too, on the access port it came in on.

A VLAN's figure follows the ports as they were at each sample: a port moved
to another VLAN counts toward the new one from the next sample.

## Measuring it instead of estimating it

The estimates above cover access ports only. Measuring traffic per VLAN and
per device, on trunks too, needs something more from the switch. These are
the options, cheapest first. **None of them has been checked yet** on the
switch NXray is built against (an N9K-C92160YC-X on NX-OS 9.3); the
read-only commands to check each one are listed, and what they show will be
written here before anything is built on them.

### VLAN interface counters

`show interface vlan <n>` (and `show interface vlan <n> counters`) count
the traffic **routed** through a VLAN interface, not the traffic switched
inside the VLAN, and exist only for VLANs that have a VLAN interface. On
many Nexus 9000 models these statistics stay at zero until a hardware
profile setting turns them on (`hardware profile svi-and-si
flex-stats-enable` on some), which may need a restart.

To check, read-only:

    show interface vlan <n>
    show interface vlan <n> counters
    show running-config all | include flex-stats

### VLAN counters

Some NX-OS releases keep switched traffic per VLAN (`show vlan counters`,
`show vlan id <n> counters`); others do not, or need a hardware profile.

To check, read-only:

    show vlan counters
    show vlan id <n> counters

### sFlow, or NetFlow

With `feature sflow` on, the switch sends samples of packet headers to a
collector. Each sample carries the VLAN, the source and destination MAC and
IP addresses and the port, which gives real per-VLAN and per-device "top
talkers", trunks included. NXray could be that collector: listen on UDP port
6343, decode sFlow version 5, add the samples up per VLAN, MAC and IP address
per minute, and keep them like the rest of history. Sampling is itself an
estimate, and NXray would show its rate.

Turning it on would be one checked change on the switch (sFlow on, the
collector set to NXray's address, a sampling rate and the ports to sample),
built from checked values like every other change NXray makes. Still to
decide: the listening port and its setting, the Docker port mapping, how
much space the samples take and how long they are kept, and how samples from
several switches are told apart.

NetFlow (Flexible NetFlow) is the other option, but which Nexus 9000 models
support it varies (mainly the -EX and -FX ones).

To check, read-only:

    show feature | include sflow
    show sflow
    show feature | include netflow
