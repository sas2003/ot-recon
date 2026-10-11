from ot_recon.core.parser import _parse_nmap_xml, parse_results
from ot_recon.core import parser as parser_module


TCP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="502">
        <state state="open"/>
        <service name="mbap"/>
      </port>
      <port protocol="tcp" portid="21">
        <state state="filtered"/>
        <service name="ftp"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

UDP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.11" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open|filtered"/>
        <service name="snmp"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_extracts_open_and_filtered(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(TCP_XML)

    result = _parse_nmap_xml(xml_path, protocol="tcp")

    assert "10.0.0.11" in result
    ports = {p["port"]: p for p in result["10.0.0.11"]}

    assert ports[502]["state"] == "open"
    assert ports[502]["service"] == "mbap"
    assert ports[21]["state"] == "filtered"
    # closed ports must not appear at all
    assert 9999 not in ports


def test_parse_nmap_xml_normalizes_open_filtered_state(tmp_path):
    xml_path = tmp_path / "scan_udp.xml"
    xml_path.write_text(UDP_XML)

    result = _parse_nmap_xml(xml_path, protocol="udp")
    ports = {p["port"]: p for p in result["10.0.0.11"]}

    assert ports[161]["state"] == "filtered"  # open|filtered -> filtered
    assert ports[161]["transport"] == "udp"


def test_parse_nmap_xml_missing_file_returns_empty(tmp_path):
    result = _parse_nmap_xml(tmp_path / "does_not_exist.xml")
    assert result == {}


def test_parse_nmap_xml_invalid_xml_returns_empty(tmp_path):
    bad_path = tmp_path / "bad.xml"
    bad_path.write_text("not valid xml <<<")

    result = _parse_nmap_xml(bad_path)
    assert result == {}


def test_parse_results_merges_tcp_and_udp(tmp_path, monkeypatch):
    tcp_path = tmp_path / "scan.xml"
    udp_path = tmp_path / "scan_udp.xml"
    tcp_path.write_text(TCP_XML)
    udp_path.write_text(UDP_XML)

    monkeypatch.setattr(parser_module, "SCAN_XML", tcp_path)
    monkeypatch.setattr(parser_module, "UDP_SCAN_XML", udp_path)

    results = parse_results()

    assert len(results) == 1
    host = results[0]
    assert host["ip"] == "10.0.0.11"

    ports_by_num = {p["port"]: p for p in host["ports"]}
    assert 502 in ports_by_num       # from TCP
    assert 161 in ports_by_num       # merged in from UDP
    assert ports_by_num[161]["transport"] == "udp"


def test_parse_results_with_no_udp_file_still_works(tmp_path, monkeypatch):
    tcp_path = tmp_path / "scan.xml"
    tcp_path.write_text(TCP_XML)

    monkeypatch.setattr(parser_module, "SCAN_XML", tcp_path)
    monkeypatch.setattr(parser_module, "UDP_SCAN_XML", tmp_path / "missing_udp.xml")

    results = parse_results()

    assert len(results) == 1
    assert all(p["transport"] == "tcp" for p in results[0]["ports"])
