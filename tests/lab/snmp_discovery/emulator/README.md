# SNMP emulator

A copy of the SNMP emulator and fixture builders from the snmp-inventory
scanner in jtklabs/Netbox (`scripts/snmp-inventory/tests/emulator`), kept here
so the lab has no dependency on that repository.

- `emulator.py` runs one net-snmp `snmpd` per walk, answering SNMPv3.
- `responder.py` is its `pass_persist` handler.
- `walkfile.py` reads and writes `snmpwalk -On` walk files.
- `make_fixtures.py` builds the synthetic vendor walks the lab serves.

The walks are synthetic: each follows the vendor's published MIB and documented
values, not a capture from real hardware.
