from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from netops_executor.device import BigIP, blocks, health, name
from netops_executor.models import JobRequest
from netops_executor.ssh import DeviceError


def test_health_handles_partitions_and_nested_pool_members():
    raw = """ltm pool /Tenant/A/pool {
        status.availability-state available
        status.enabled-state enabled
        members { /Common/node:80 { status.availability-state offline status.enabled-state disabled } }
    }
    ltm pool /Common/offline { status.availability-state offline status.enabled-state enabled }
    ltm pool /Common/disabled { status.availability-state available status.enabled-state disabled }
    """
    stats = health(raw, "pool")
    assert stats["up"] == 1 and stats["total"] == 3
    assert "/Tenant/A/pool" in stats["objects"]


def test_virtual_statistics_require_raw_numeric_counts():
    raw = "ltm virtual /Common/v { status.availability-state available status.enabled-state enabled clientside.cur-conns 123 }"
    assert health(raw, "virtual")["objects"]["/Common/v"]["connections"] == 123
    with pytest.raises(DeviceError):
        health(raw.replace("123", "1.2K"), "virtual")
    with pytest.raises(DeviceError):
        health(raw.replace("status.availability-state available", ""), "virtual")


@pytest.mark.parametrize(
    "raw", ["Syntax Error: invalid command", "ltm pool a {", "ltm pool a {} ltm pool a {}", "ltm node x {}"]
)
def test_invalid_stats_fail_closed(raw):
    with pytest.raises(DeviceError):
        health(raw, "pool")


def test_empty_inventory_is_explicitly_zero():
    assert health("", "pool") == {"up": 0, "total": 0, "objects": {}}


def test_drain_changes_only_virtual_addresses():
    ssh = Mock()
    ssh.tmsh.return_value = """ltm virtual-address /Common/192.0.2.5 { address 192.0.2.5 enabled yes }
        ltm virtual-address /Tenant/2001:db8::1%2 { enabled no }"""
    device = BigIP(ssh)
    assert device.address_states() == {"/Common/192.0.2.5": True, "/Tenant/2001:db8::1%2": False}
    device.set_enabled("/Common/192.0.2.5", False)
    device.set_enabled("/Common/192.0.2.5", True)
    assert ssh.tmsh.call_args_list[-2].args == ("modify /ltm virtual-address /Common/192.0.2.5 enabled no",)
    assert ssh.tmsh.call_args_list[-1].args == ("modify /ltm virtual-address /Common/192.0.2.5 enabled yes",)
    assert not any("modify /ltm virtual " in c.args[0] for c in ssh.tmsh.call_args_list)


def test_drain_addresses_recursive_names_absolutely():
    # Real BIG-IP 17.5 output after `cd /`: names are relative to the root folder.
    ssh = Mock()
    ssh.tmsh.return_value = "ltm virtual-address Common/172.29.240.101 { address 172.29.240.101 enabled yes }"
    device = BigIP(ssh)
    assert device.address_states() == {"Common/172.29.240.101": True}
    device.set_enabled("Common/172.29.240.101", False)
    assert ssh.tmsh.call_args.args == ("modify /ltm virtual-address /Common/172.29.240.101 enabled no",)


STANDALONE_GROUPS = """cm device-group device_trust_group { auto-sync enabled devices { bigip1 { } } type sync-only }
cm device-group datasync-global-dg { auto-sync enabled devices { bigip1 { } } type sync-only }
cm device-group gtm { auto-sync disabled devices { bigip1 { } } type sync-only }"""


def test_drain_ignores_builtin_auto_sync_groups():
    # Output shape from a standalone BIG-IP 17.5 unit; the trust group always auto-syncs.
    ssh = Mock()
    ssh.tmsh.return_value = STANDALONE_GROUPS
    BigIP(ssh).check_drain()
    ssh.tmsh.return_value = (
        STANDALONE_GROUPS + "\ncm device-group apps { auto-sync enabled devices { bigip1 { } bigip2 { } } }"
    )
    with pytest.raises(DeviceError, match="automatic config sync"):
        BigIP(ssh).check_drain()


def test_command_name_validation():
    for value in ["x; reboot", "$(id)", "a\nreboot", "*", "-all", 'a"']:
        with pytest.raises(DeviceError):
            name(value)


def test_quoted_and_nested_blocks():
    output = 'asm policy /Tenant/policy { description "text with { braces }" virtual-servers { /Common/v } }'
    assert list(blocks(output, "asm policy")) == ["/Tenant/policy"]


def test_argument_inheritance(image):
    r = JobRequest(
        device="lab", install=True, images=[image], target_volume="HD1.2", allowed_source_versions=["16.1.5"]
    )
    assert r.expected_version == "17.1.2"
    assert "transfer" in r.plan() and "copy_ucs" in r.plan()
    assert "reboot" not in r.plan()
    r.images_on_device = True
    assert "transfer" not in r.plan()
    assert "create_ucs" in JobRequest(device="lab", backup_directory="maintenance/site-a").plan()
    with pytest.raises(ValidationError):
        JobRequest(device="lab", drain_connections=1, drain_percent=90)
    with pytest.raises(ValidationError):
        JobRequest(device="lab", drain=True)
    with pytest.raises(ValidationError):
        JobRequest(device="lab", images=[image], install=True, target_volume="HD1.2")
    with pytest.raises(ValidationError):
        JobRequest(
            device="lab",
            install=True,
            images=[image],
            target_volume="HD1.2",
            allowed_source_versions=["16.1.5"],
            expected_version="18.0.0",
        )


def test_installed_hotfix_build_comes_from_status_table():
    ssh = Mock()
    ssh.tmsh.side_effect = [
        "sys software volume HD1.2 { active no active-requested no status complete version 17.1.2 build 0.0.1 basebuild 0.0.1 }",
        "Sys::Software Status\nVolume Product Version Build Active Status Allowed Version\nHD1.2 BIG-IP 17.1.2 0.0.5 no complete yes",
    ]
    volume = BigIP(ssh).volumes()["HD1.2"]
    assert volume["build"] == "0.0.5"
    from netops_executor.device import matches

    assert matches(volume, "17.1.2", "0.0.5")
    assert not matches(volume, "17.1.2", "0.0.1")


# Captured from BIG-IP VE 17.5.1.10 (lab). Boolean volume properties are bare keywords.
VOLUMES_17_5 = """sys software volume HD1.1 {
    active
    active-requested
    basebuild 0.0.35
    build 0.0.35
    edition none
    media {
        HD1.1 {
            default-boot-location
            media hd
            size default
        }
    }
    product BIG-IP
    status complete
    version 17.5.1.10
}
sys software volume HD1.2 {
    basebuild 0.0.12
    build 0.0.12
    edition none
    media {
        HD1.2 {
            media hd
            size default
        }
    }
    product BIG-IP
    status complete
    version 17.5.1.9
}
"""
STATUS_17_5 = """
---------------------------------------------------------------------
Sys::Software Status
Volume  Product    Version   Build  Active    Status  Allowed Version
---------------------------------------------------------------------
HD1.1    BIG-IP  17.5.1.10  0.0.35     yes  complete              yes
HD1.2    BIG-IP   17.5.1.9  0.0.12      no  complete              yes
"""


def test_volumes_parse_bare_boolean_properties():
    ssh = Mock()
    ssh.tmsh.side_effect = [VOLUMES_17_5, STATUS_17_5]
    volumes = BigIP(ssh).volumes()
    assert volumes["HD1.1"]["active"] and volumes["HD1.1"]["active_requested"]
    assert not volumes["HD1.2"]["active"] and not volumes["HD1.2"]["active_requested"]
    assert (volumes["HD1.2"]["version"], volumes["HD1.2"]["build"]) == ("17.5.1.9", "0.0.12")


def test_multiline_values_are_never_read_as_property_names():
    # "arp enabled" precedes "enabled yes" in 17.5 all-properties output.
    ssh = Mock()
    ssh.tmsh.return_value = """ltm virtual-address Common/172.29.240.101 {
    address 172.29.240.101
    arp enabled
    auto-delete true
    enabled no
    floating enabled
    traffic-group Common/traffic-group-1
}
"""
    assert BigIP(ssh).address_states() == {"Common/172.29.240.101": False}


def test_one_line_policy_active_flag():
    from netops_executor.device import flag

    rows = blocks(
        "asm policy Common/waf-01 { active encoding utf-8 policy-template POLICY_TEMPLATE_FUNDAMENTAL }\n"
        "asm policy Common/waf-02 { encoding utf-8 }",
        "asm policy",
    )
    assert flag(rows["Common/waf-01"], "active") and not flag(rows["Common/waf-02"], "active")


def test_chassis_and_incomplete_status_rejected():
    ssh = Mock()
    ssh.tmsh.return_value = "sys software volume HD1.2/1 { active no status complete }"
    with pytest.raises(DeviceError):
        BigIP(ssh).volumes()
    ssh.tmsh.side_effect = ["sys software volume HD1.2 { active no status complete version 17.1.2 }", ""]
    with pytest.raises(DeviceError):
        BigIP(ssh).volumes()


def test_image_and_hotfix_metadata(image):
    from netops_executor.models import Image

    ssh = Mock()
    ssh.tmsh.return_value = "sys software image BIGIP.iso { version 17.1.2 build 0.0.5 verified yes }"
    BigIP(ssh).verify_image(Image(**image))
    ssh.tmsh.return_value = "sys software image BIGIP.iso { version 17.1.2 build 0.0.5 verified no }"
    with pytest.raises(DeviceError):
        BigIP(ssh).verify_image(Image(**image))
    image["kind"] = "hotfix"
    ssh.tmsh.return_value = "sys software hotfix BIGIP.iso { version 17.1.2 verified yes }"
    BigIP(ssh).verify_image(Image(**image))
    assert " build" not in ssh.tmsh.call_args.args[0]


def test_nested_member_status_cannot_replace_pool_status():
    raw = """ltm pool /Common/pool {
        members { /Common/member:80 { status.availability-state available status.enabled-state enabled } }
        status.availability-state offline
        status.enabled-state enabled
    }"""
    assert health(raw, "pool")["up"] == 0
    missing = raw.replace("        status.availability-state offline\n", "")
    with pytest.raises(DeviceError):
        health(missing, "pool")
