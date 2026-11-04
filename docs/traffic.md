# Traffic per VLAN and per device

[← back to the README](../README.md)

The switch measures traffic **per port**: `show interface` gives each port's
in and out rate, averaged over 30 seconds, and its byte and packet counters.
It does not say which VLAN or which device that traffic belongs to. NXray
works out two estimates from the port figures it already reads, without
asking the switch for anything more or changing it. Both are always labelled
as estimates, and this page says what each one leaves out.

For traffic **measured** per VLAN and per device, trunks included, NXray can
also be the switch's sFlow collector: see [Measured with sFlow](#measured-with-sflow).

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
per device, on trunks too, needs something more from the switch. NXray does it
with sFlow ([below](#measured-with-sflow)). The switch's own counters are the
other options; **they have not been checked yet** on the switch NXray is built
against (an N9K-C92160YC-X on NX-OS 9.3), so NXray does not use them. The
read-only commands to check each one are listed.

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

### NetFlow

NetFlow (Flexible NetFlow) is another way to measure, but which Nexus 9000
models support it varies (mainly the -EX and -FX ones). NXray uses sFlow,
below, which the 9000s have.

To check, read-only:

    show feature | include netflow

## Measured with sFlow

With `feature sflow` on, the switch sends **samples** of the frames it
forwards to a collector over UDP: one frame in every N (the **sampling
rate**), with the first bytes of the frame, its length and the VLAN it is in.
NXray can be that collector. Each sampled frame's length times N stands for
the traffic it was picked from, which gives traffic **per VLAN and per device,
trunks and ports with several devices included**, on the **Traffic** page
(under Monitor).

**Turning it on.**

1. In `nxray.env`, set `NXRAY_SFLOW_PORT=6343`. In `docker-compose.yml`,
   uncomment the `"6343:6343/udp"` line under `ports:` (a compose file from
   before this has none: add `- "6343:6343/udp"` there). Run `docker compose
   up -d`. The Traffic page's **NXray's collector** card then says
   *Listening*.
2. With **traffic measuring changes** on (role version 15; an admin presses
   **Turn on traffic measuring changes** on the Switch page), an operator or
   admin fills in **Send sFlow to NXray** on the Traffic page:
   - **NXray's address, as the switch reaches it**: an IPv4 address of the
     machine NXray runs on (filled in from the address your browser used);
   - **VRF**: `management` when NXray is on the network of the switch's
     management port, `default` when it is reached over the front ports;
   - **UDP port**: the left number of the `/udp` line;
   - **The switch's agent address**: one of the switch's own IPv4 addresses,
     usually its management address (filled in from the address NXray uses
     for NX-API). Every datagram carries it, and NXray uses it to tell which
     of its switches sent it;
   - **Sample one frame in** 4096 (the switch's default), 8192, 16384, 32768
     or 65536;
   - **Ports to sample**: every front port, those up now, or a list such as
     `Ethernet1/1, Ethernet1/3-6, port-channel41`. The switch refuses a port
     that is in a port-channel; its port-channel is sampled instead, which
     covers all its ports, and the confirm page says so.

   NXray shows what it will do and asks you to confirm, then turns on the
   sflow feature if it is off and sends only what changes:

       feature sflow
       sflow sampling-rate 4096
       sflow collector-ip <NXray's address> vrf <VRF>
       sflow collector-port 6343
       sflow agent-ip <agent address>
       sflow data-source interface ethernet 1/1
       sflow data-source interface port-channel 41
       ... (one line per port or port-channel; "no sflow data-source ..." for
       one left out)

   Not saved until **Save config**. **Turn sFlow off on the switch** turns the
   feature off, which removes every sFlow line (the traffic already measured is
   kept). These lines follow Cisco's NX-OS 9.3 System Management
   Configuration Guide; the front-port lines have been tried on an
   N9K-C92160YC-X, the port-channel line not yet. If the switch refuses one,
   the page shows its words; the lines before it have already taken effect,
   and the switch is marked as having unsaved changes.

**What the page shows,** for 1 hour to 30 days (as much as is kept):

- **Busiest VLANs**: each VLAN's average, its share and how many samples it
  rests on. A frame that came in without a VLAN tag (on an access port, or on
  a trunk's native VLAN) is counted in its port's VLAN, which NXray reads from
  the switch about once a minute; *VLAN not given* is what is left, such as a
  routed port or the first minute after NXray starts.
- **Traffic per VLAN, measured**: a small card for each of the busiest eight
  VLANs: its latest figure in large type with the highest and the average
  beside it, and a short chart of the traffic as a filled area, the scale on
  the right. There is one figure per VLAN, not an in and an out: the switch
  counts each sampled frame once, on the port it came in on.
- **Busiest devices**: by MAC address, what each sent into the switch
  (**sends**) and what was sent to it (**receives**), with its maker, IP
  addresses and port from the switch's MAC address and ARP tables now.
  **Over time** draws one device's sends and receives.

**What to know.**

- Each frame is counted on the port it **comes in on**, so with every port
  sampled each frame is counted once. A port left out misses what enters
  through it.
- It is an estimate from samples: the more frames, the closer. A device that
  sends little may get no sample at all in a short range. The page shows how
  many samples each VLAN rests on.
- Broadcast and multicast are left out of a device's **receives** (no one
  device receives them), not out of the VLANs.
- **Space.** Each minute keeps every VLAN and the 100 busiest devices each way
  (the rest are added up as *Other devices*), so a switch takes about 1 to
  15 MB a day; `NXRAY_SFLOW_KEEP_DAYS` (7 by default, up to 90) says how long
  it is kept. Forgetting a switch deletes its measured traffic.
- **Several switches** send to the same port; NXray tells them apart by the
  agent address. Datagrams from an address that is none of its switches are
  not counted, and the Traffic page names that address.
- **No password.** sFlow has none: NXray counts only datagrams that name one
  of its switches, but anyone who can reach the port could send made-up
  samples. Keep the port on a network you trust, or allow only the switch's
  address in front of it.
- What NXray has added up but not yet stored (the current minute) is lost on
  a restart; stored minutes are kept.

To check what the switch has, read-only:

    show feature | include sflow
    show sflow
