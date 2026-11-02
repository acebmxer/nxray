# Live figures

[← back to the README](../README.md)

The dashboard, the Ports page, a port's own page and the Neighbors page can
refresh their figures by themselves, so you do not reload. It is off until
you ask for it.

## Turning it on

Each of those pages has a **Refresh** box in the top bar: **Off, Live, 3 s,
5 s, 10 s, 15 s, 30 s, 60 s**. The choice is kept for this browser (a cookie,
like the theme) and applies to all four pages. Next to it the page shows
*Updated hh:mm:ss*, and a **Pause** button.

Only the figures change: the numbers, bars, the front panel and the table
rows. An open side panel, your place on the page and anything you are typing
stay as they are. Without JavaScript, or with it blocked, the pages work as
they always did.

Refreshing stops by itself:

- while the browser tab is in the background (it catches up when you return);
- while a field on the page has the cursor, or has been changed and not sent
  (the Ports page's tick boxes, a search, a form in the side panel);
- when you press **Pause**;
- when you are signed out (the box says so).

Result and confirm pages, and a page shown after a refused change, never
refresh.

## What it costs the switch

NX-API on a Nexus can stop answering everyone when it is kept busy, so the
browsers never ask the switch directly. NXray keeps the newest reading per
switch and kind of figure and reads the switch again only when that reading is
older than a floor:

| Figures | Floor (default) | Setting |
| --- | --- | --- |
| Switch health (CPU, memory, temperatures, fans, power), ports (state, rates, errors) | 2 s | `NXRAY_LIVE_MIN_INTERVAL` |
| MAC address table, ARP, neighbours | 10 s | `NXRAY_LIVE_CLIENTS_MIN_INTERVAL` |

Ten browsers on **Live** cost the switch what one does. Nothing is read when
nobody has a page open with a refresh on: reads happen only when a page asks,
and a reading nobody asked for in five minutes is dropped. Choosing less than
the floor gives the floor; **Live** means "as often as the floor allows".

Only `show` commands are sent. If the switch does not answer, NXray keeps
showing the last good figures with a red note saying so, and waits longer
before trying again (2, 4, 8 ... at most 60 seconds) until it answers.

The Ports page and the port pages share one reading of the ports. The
Connected column, port-channels and a port's devices come from the slower
neighbour reading. The Neighbors page reads its ports (for the busiest
devices) at the slower pace too.

Refreshing does not count as using NXray: it does not extend your sign-in, so
a page left open on **Live** is signed out after `NXRAY_SESSION_HOURS` like any
other.

## What "In" and "Out" mean

- With **Off** or an interval, In and Out are the **switch's own average over
  the last 30 seconds**, as on a page you open, so they move slowly.
- With **Live**, the Ports page and a port's page work them out from how far
  the port's byte counters moved between two readings, and say so: *measured
  over the last N s, from the byte counters*. The first reading after opening
  a page, a port that was down, and a port whose counters were just cleared
  keep the switch's figure.

The Neighbors page's traffic per device always uses the switch's averages.

### A shorter average on the switch

The 30 seconds are the switch's own setting, per port (`load-interval counter
1`). With traffic measuring changes on, a port's page has a **Rate average**
card that sets it to 5, 10 or 15 seconds, 1, 2 or 5 minutes, or back to the
default; see [Switch setup](switch-setup.md#port-changes). The switch's In and
Out then follow that average everywhere NXray shows them (pages, history,
alerts), and a port's page names it. It changes only the figures, never the
traffic. **Live** keeps measuring from the byte counters, whatever the
average.

## What does not refresh

- The VLAN colours of the front panel: they need the VLAN tables, so with that
  colouring the panel stays until you reload (the rows still refresh).
- The filter counts above the port table, and anything in the side panel.
- The History charts, which come from the stored samples
  (`NXRAY_HISTORY_INTERVAL`), not from live readings.

The refresh is read-only; nothing in it changes a switch.
