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
