import subprocess
from unittest.mock import patch, MagicMock

from ot_recon.core import netutils


# --- _ips_via_ip_command ---

REAL_IP_OUTPUT = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
    "4: eth0    inet 192.0.2.2/24 brd 192.0.2.255 scope global eth0\\       valid_lft forever preferred_lft forever\n"
)


def _run_result(stdout, returncode=0):
    r = MagicMock()
    r.stdout = stdout
    r.returncode = returncode
    return r


def test_ips_via_ip_command_excludes_loopback():
    with patch("subprocess.run", return_value=_run_result(REAL_IP_OUTPUT)):
        ips = netutils._ips_via_ip_command()

    assert ips == {"192.0.2.2"}
    assert "127.0.0.1" not in ips


def test_ips_via_ip_command_handles_multiple_interfaces():
    multi_nic_output = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
        "3: eth1    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth1\n"
    )
    with patch("subprocess.run", return_value=_run_result(multi_nic_output)):
        ips = netutils._ips_via_ip_command()

    assert ips == {"10.0.0.5", "192.168.1.50"}


def test_ips_via_ip_command_returns_empty_set_when_binary_missing():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert netutils._ips_via_ip_command() == set()


def test_ips_via_ip_command_returns_empty_set_on_timeout():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ip", timeout=5)):
        assert netutils._ips_via_ip_command() == set()


def test_ips_via_ip_command_returns_empty_set_on_nonzero_exit():
    with patch("subprocess.run", return_value=_run_result("", returncode=1)):
        assert netutils._ips_via_ip_command() == set()


# --- _ip_via_outbound_socket ---

def test_ip_via_outbound_socket_returns_sockname_address():
    fake_sock = MagicMock()
    fake_sock.getsockname.return_value = ("192.0.2.2", 54321)
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)

    with patch("socket.socket", return_value=fake_sock):
        ips = netutils._ip_via_outbound_socket()

    assert ips == {"192.0.2.2"}


def test_ip_via_outbound_socket_returns_empty_set_on_failure():
    with patch("socket.socket", side_effect=OSError("network unreachable")):
        assert netutils._ip_via_outbound_socket() == set()


# --- get_local_ips (the public entry point) ---

def test_get_local_ips_prefers_ip_command_when_available():
    with patch.object(netutils, "_ips_via_ip_command", return_value={"10.0.0.5"}), \
         patch.object(netutils, "_ip_via_outbound_socket") as mock_fallback:
        ips = netutils.get_local_ips()

    assert ips == {"10.0.0.5"}
    mock_fallback.assert_not_called()  # fallback must not run when primary succeeds


def test_get_local_ips_falls_back_when_ip_command_finds_nothing():
    with patch.object(netutils, "_ips_via_ip_command", return_value=set()), \
         patch.object(netutils, "_ip_via_outbound_socket", return_value={"192.0.2.2"}):
        ips = netutils.get_local_ips()

    assert ips == {"192.0.2.2"}


def test_get_local_ips_never_raises_when_both_methods_fail():
    with patch.object(netutils, "_ips_via_ip_command", return_value=set()), \
         patch.object(netutils, "_ip_via_outbound_socket", return_value=set()):
        assert netutils.get_local_ips() == set()
