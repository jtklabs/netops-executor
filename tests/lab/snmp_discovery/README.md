# Simulated SNMP discovery lab

A local, end-to-end check of NetOps Executor's SNMP discovery against one
simulated device per supported vendor, a four-member Catalyst 9300 stack, and
an Aruba controller's access points. It runs real net-snmp `snmpd` agents, a
throwaway NetBox 4.7.4 with this repo's `netbox-refresh` plugin, and the
executor API plus one worker, all in Docker.

```bash
./lab.py                  # start, discover all, rediscover all, then stack failover and hardware changes
./lab.py poll 10.93.0.16  # submit one more discovery job and print result.discovery
./lab.py down             # stop the lab and delete its volumes
```

Every agent answers SNMPv3 (user `netops`, SHA-256 / AES, the emulator's fixed
lab passphrases) on its own address on the lab network:

| Address | Name | Device | NetBox role |
| --- | --- | --- | --- |
| 10.93.0.10 | lab-c9300-stk01 | Cisco Catalyst 9300 stack, 4 members + 1 provisioned slot | Switch |
| 10.93.0.11 | bld-b-acc-01 | Cisco WS-C2960X-48FPD-L, standalone | Switch |
| 10.93.0.12 | dc1-spine-01 | Arista DCS-7050SX-72Q | Switch |
| 10.93.0.13 | dal-wlc-01 | Aruba 7010 Mobility controller with 3 APs | Wireless Controller |
| 10.93.0.14 | dal-cppm-01 | Aruba ClearPass C2000 | Network Access Control |
| 10.93.0.15 | dal-ltm-01 | F5 BIG-IP i5800 | Load Balancer |
| 10.93.0.16 | dal-fw-01 | Palo Alto PA-3220 | Firewall |
| 10.93.0.17 | dal-fgt-01 | Fortinet FortiGate-600E | Firewall |
| 10.93.0.18 | dal-cp-01 | Check Point 6200 (Gaia R81.20 Take 89) | Firewall |
| 10.93.0.19 | dal-ddi-01 | Infoblox IB-1420 | DNS/DHCP |
| 10.93.0.20 | dal-acc-01 | Juniper EX4300-48T | Switch |
| 10.93.0.21 | dal-con-01 | Opengear CM7148-2-DAC | Console Server |
| 10.93.0.22 | dal-srx-01 | Juniper SRX1500 chassis-cluster primary | Firewall |
| 10.93.0.23 | dal-proxy-01 | Blue Coat SG-S400 | Proxy |

The 9300 stack:

| Switch | Model | Role | Serial |
| --- | --- | --- | --- |
| 1 | C9300-48P | active | FOC2741L1AA |
| 2 | C9300-48U | standby | FOC2741L2BB |
| 3 | C9300-24T | member | FOC2742L3CC |
| 4 | C9300-48P | member | FOC2742L4DD |
| 5 | — | provisioned, no hardware | — |

After a failover, the lab applies three hardware changes to the stack, each
followed by a rediscovery that must change nothing:

| Walk | Change | Expected in NetBox |
| --- | --- | --- |
| `c9300-stack-replaced` | switch 3 swapped for a C9300-24P, FOC2750L3ZZ | new `lab-c9300-stk01-3`; old record renamed `lab-c9300-stk01-3-decom-FOC2742L3CC`, Decommissioning, out of the chassis |
| `c9300-stack-renumbered` | switches 2 and 4 swap member numbers | the same two records renamed and moved, IDs kept |
| `c9300-stack-new-master` | switch 1 swapped while switch 2 is active | new `lab-c9300-stk01` with the polled IP and chassis master; old record `lab-c9300-stk01-decom-FOC2741L1AA`, without IP |

The full run expects an empty NetBox, so run `./lab.py down` before running it
again.

`make_walks.py` builds the walks. The fleet comes from the snmp-inventory
fixtures in `scripts/snmp-inventory/tests/emulator/make_fixtures.py`, with each
device's management address moved to its lab address. The Opengear walk also
gets an `ogSerialNumber`, which the executor reads and the shared fixture lacks.
The stack is built here; `c9300-stack-failover.walk` is the same stack after
switch 2 takes over as active. `agent.py` runs one emulator `snmpd` per walk
in a single container, adding each address to its interface.

For every device, `lab.py` checks the SNMP facts and the NetBox record: device
type, serial, role, platform, `software_version`, tags, the primary IP on the
right interface, and the running version stored by `netbox-refresh`. For the
stack it checks one virtual chassis, its master, and every member. For the
controller it checks that `dal-ap-101` to `-103` exist with role Wireless AP,
their own model, serial and version (`dal-ap-102` inherits the controller's),
and a `wireless_controller` link to `dal-wlc-01`. Rediscovery and the stack
failover must leave NetBox unchanged. After each stack hardware change it also
checks the retired records and that switches already known keep their record.

Everything binds to 127.0.0.1: NetBox on 18080 (user `admin`, password
`SUPERUSER_PASSWORD` in `lab.env`) and the executor on 18081. `lab.env` holds
fresh secrets generated on first run and is gitignored, as are the generated
walks. The executor shares the NetBox container's network namespace so it can
use NetBox over loopback HTTP, which is the only plain-HTTP NetBox URL the
executor accepts. `Dockerfile.netbox` builds NetBox 4.7.4 with
`plugins/netbox-refresh` from this repo, and `netbox/plugins.py` enables it.

The walks are synthetic: they prove the executor handles each vendor's shapes,
not that a given firmware fills in a given table.
