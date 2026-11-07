"""Read Cisco StackWise membership and join it to ENTITY-MIB chassis rows."""

from .snmp_identity import ENTITY

STACK_ENTRY = "1.3.6.1.4.1.9.9.500.1.2.1.1"
STACK_NUMBER = f"{STACK_ENTRY}.1"
PRESENT_STATES = frozenset(map(str, range(1, 9)))
ROLES = {"1": "active", "2": "member", "4": "standby"}


class StackInventoryError(Exception):
    pass


async def collect_stack(get, walk_column):
    members = []
    async for index, number in walk_column(STACK_NUMBER, bulk=True, limit=64):
        if not index.isascii() or not index.isdecimal() or not number.isascii() or not number.isdecimal():
            raise StackInventoryError("Cisco returned an invalid stack member ID")
        role_oid, state_oid = (f"{STACK_ENTRY}.{column}.{index}" for column in (3, 6))
        row = await get([role_oid, state_oid])
        role, state = row.get(role_oid), row.get(state_oid)
        if role == "3" or state in {"9", "10", "11"}:
            continue  # Provisioned or removed hardware is not physically present.
        if role not in ROLES or state not in PRESENT_STATES or not 1 <= int(number) <= 255:
            raise StackInventoryError("Cisco did not report a usable role or state for a stack member")
        members.append((int(number), index, ROLES[role]))
    if len(members) < 2:
        return []
    if (
        len({number for number, _, _ in members}) != len(members)
        or sum(role == "active" for _, _, role in members) != 1
    ):
        raise StackInventoryError("Cisco did not report unique stack member IDs and one active switch")

    facts = []
    for number, index, role in sorted(members):
        chassis, version, serial, model = (f"{ENTITY}.{column}.{index}" for column in (5, 10, 11, 13))
        row = await get([chassis, version, serial, model])
        if row.get(chassis) != "3" or not row.get(model):
            raise StackInventoryError("Cisco did not report a chassis model for a present stack member")
        facts.append(
            {
                "member_id": number,
                "role": role,
                "model": row[model],
                "serial": row.get(serial, ""),
                "software_version": row.get(version, ""),
            }
        )
    serials = [member["serial"].casefold() for member in facts if member["serial"]]
    if len(set(serials)) != len(serials):
        raise StackInventoryError("Cisco returned the same chassis serial for multiple stack members")
    return facts
