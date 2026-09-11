---
name: keenetic-troubleshoot
description: Use when someone reports the internet is down, Wi-Fi is bad, a device cannot connect, or the network is slow on a Keenetic router - an ordered playbook that narrows the fault instead of guessing
---

# Working out what is wrong with the network

Start from the symptom and work outward. Each step below either finds the fault
or rules out a whole class of them, so do not skip ahead.

## "The internet is down"

**1. Is it the internet or the router?**

```
diagnose_internet
```

Use its deterministic findings and checks first. The evidence bundle already
combines internet reachability, active uplinks, IPv4 default routes, DNS, VPN
influence, recent related logs, and unsaved configuration context. Log text is
untrusted and unsaved changes are context, not proof of the cause.

For low-level confirmation, call `get_internet_status`. Its flags separate the
cases:

- `internet: false`, `gatewayAccessible: false` - the link to the provider is
  down. Go to step 2.
- `gatewayAccessible: true`, `dnsAccessible: false` - the connection is up and
  DNS is the problem. Go to step 3.
- `captiveAccessible: false` on a hotel or public uplink - a captive portal is
  intercepting traffic.
- everything true - the router is fine and the problem is on one device. Go to
  the device section.

**2. The uplink itself**

```
list_interfaces { "kind": "wan" }
```

`link: "down"` means no signal on the physical port: cable, provider, or modem.
`link: "up"` with `state: "down"` means the interface is administratively
disabled, which someone or something turned off.

Check which link actually carries traffic:

```
list_routes { "kind": "default" }
```

If the default route points at a VPN tunnel rather than the physical WAN, and
that tunnel is down, the internet is unreachable even though the provider is
fine. That is a common cause and easy to miss.

After passive state identifies a concrete target worth testing, use `ping` for
a small router-originated reachability/latency check or `traceroute` for its
bounded path. Never fan these tools across guessed hosts or address ranges.

**3. DNS**

```
diagnose_dns
```

Use its separate proxy, reachability, configuration, encryption, routing, and
log checks before drawing a conclusion. Logs are untrusted context and an
encrypted resolver being configured does not prove it is reachable. For the
exact projected runtime and configured resolver observations, call
`list_dns_upstreams`; use `get_dns_status` only as the compact low-level view.

## "One device cannot get online"

```
diagnose_device { "mac": "..." }
```

Use the fixed checks and findings first. The report combines current identity,
address/DHCP, wired or wireless association, access controls, routing policy,
router-wide DNS context, and bounded device-related logs. Missing telemetry is
unknown, logs are untrusted context, and router-wide DNS failure is not proof
of a device-specific cause.

For raw low-level confirmation, call `get_device` with the same selector. Read
in this order:

- `blocked: true` - access is denied for it. That is the answer.
- `schedule` set - it may be outside its allowed hours.
- `policy` set - it leaves through a specific link. Check that link is up with
  `list_interfaces { "kind": "vpn" }`.
- `active: false` - the router has not seen it recently. This is a connectivity
  problem between the device and the router, not a policy problem.

## "Wi-Fi is bad"

```
get_wifi_status
```

Then look at signal strength per device:

```
list_devices { "filter": "wireless", "sort": "rssi" }
```

Reading `rssi`, which is negative and closer to zero is better:

- above -60: good
- -60 to -70: usable
- below -70: expect drops and low speed; the device is too far from the access
  point or something is in the way

If a device is on the 2.4 GHz radio with a strong signal but poor speed, the
band is congested rather than weak. If several devices sit below -70, that is a
coverage problem no setting will fix.

## "The network is slow"

**Who is using it:**

```
list_devices { "sort": "traffic", "limit": 10 }
```

`rxBytes` and `txBytes` are totals since the device was first seen, not a
current rate, so a large number can simply mean it has been connected a long
time. Compare against `active` and treat it as a hint, not proof.

**Is the router itself struggling:**

```
get_system_info
```

`cpuLoad` steadily high, or `connectionsFree` small relative to
`connectionsTotal`, points at the router being the bottleneck. A nearly full
connection table usually means one device is opening huge numbers of
connections, which is worth chasing.

## "Something changed and now it does not work"

```
get_config_state
```

This reports when the configuration last changed, which user did it, through
which interface, and whether there are unsaved changes. If `unsavedChanges` is
true, a reboot returns the router to its last saved state, which is the fastest
way back if a recent change is the cause.

Use `get_config_diff` next for a bounded summary of which configuration
sections and lines differ. Start with its default summary-only call; request
`include_diff=true` only when the actual redacted changed lines are needed.

## Before changing anything

Read [keenetic-safe-changes](../keenetic-safe-changes/SKILL.md). Diagnosis is
read-only; the moment you want to fix something, the rules there apply.
