"""The `leases` role: a DHCP lease file (dnsmasq, ISC, Kea) and a router's ARP
table over SNMP, and the checks every such source shares (_leases.py). The
SNMP tests talk to a fake agent on localhost; nothing leaves the machine."""
import socket
import threading

import pytest

NOW = 1790000000          # 2026-09-21, fixed so "expired" means the same every run

DNSMASQ = f"""\
{NOW + 3600} aa:bb:cc:00:00:01 192.168.10.10 nas 01:aa:bb:cc:00:00:01
{NOW - 60} aa:bb:cc:00:00:02 192.168.10.11 gone *
0 AA-BB-CC-00-00-03 192.168.10.12 * *
duid 00:01:00:01:2c:5e:aa:bb:cc:dd:ee:ff
{NOW + 3600} 1234 fd00::5 phone6 00:01:00:01
"""

ISC = """\
# The format of this file is documented in the dhcpd.leases(5) manual page.
lease 192.168.10.20 {
  starts 1 2026/09/21 08:00:00;
  ends 1 2026/09/21 20:00:00;
  binding state free;
  hardware ethernet aa:bb:cc:00:00:20;
}
lease 192.168.10.20 {
  starts 1 2026/09/21 08:00:00;
  ends 3 2026/09/23 08:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:00:00:21;
  client-hostname "printer";
}
lease 192.168.10.21 {
  ends 0 2026/09/20 08:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:00:00:22;
}
lease 192.168.10.22 {
  ends never;
  hardware ethernet aa:bb:cc:00:00:23;
}
"""

KEA = f"""\
address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context
192.168.10.30,aa:bb:cc:00:00:30,,3600,{NOW + 100},1,0,0,tv.,0,
192.168.10.31,aa:bb:cc:00:00:31,,3600,{NOW + 100},1,0,0,,1,
192.168.10.32,aa:bb:cc:00:00:32,,3600,{NOW - 100},1,0,0,old,0,
192.168.10.30,aa:bb:cc:00:00:39,,3600,{NOW + 900},1,0,0,tv2,0,
"""


# ---- parsers ------------------------------------------------------------------------------------
def test_dnsmasq_current_ipv4_leases_only():
    from app.sources import leasefile
    rows = leasefile.parse_dnsmasq(DNSMASQ, NOW)
    assert [(r["ip"], r["mac"], r["label"]) for r in rows] == [
        ("192.168.10.10", "aa:bb:cc:00:00:01", "nas"),
        ("192.168.10.12", "aa:bb:cc:00:00:03", "")]              # infinite; "*" is no name
    assert "infinite" in rows[1]["detail"]


def test_isc_last_block_wins_and_only_active_unexpired():
    from app.sources import leasefile
    rows = {r["ip"]: r for r in leasefile.parse_isc(ISC, NOW)}
    assert set(rows) == {"192.168.10.20", "192.168.10.22"}
    assert rows["192.168.10.20"]["mac"] == "aa:bb:cc:00:00:21"
    assert rows["192.168.10.20"]["label"] == "printer"


def test_kea_last_row_wins_and_only_live_leases():
    from app.sources import leasefile
    rows = {r["ip"]: r for r in leasefile.parse_kea(KEA, NOW)}
    assert set(rows) == {"192.168.10.30"}
    assert rows["192.168.10.30"]["mac"] == "aa:bb:cc:00:00:39"
    assert rows["192.168.10.30"]["label"] == "tv2"


@pytest.mark.parametrize("text,fmt", [(DNSMASQ, "dnsmasq"), (ISC, "isc"), (KEA, "kea")])
def test_the_format_is_detected(text, fmt):
    from app.sources import leasefile
    assert leasefile.detect(text) == fmt


def test_a_missing_or_relative_path_is_said_plainly(tmp_path):
    from app.sources import leasefile
    assert "no file at" in leasefile.test({"path": str(tmp_path / "none"), "format": "auto"})["error"]
    assert "absolute" in leasefile.test({"path": "leases", "format": "auto"})["error"]
    f = tmp_path / "x.leases"
    f.write_text(DNSMASQ)
    assert "format must be" in leasefile.test({"path": str(f), "format": "csv"})["error"]


# ---- the shared checks, through a real instance ---------------------------------------------------
@pytest.fixture
def app(make_app):
    _, c = make_app(NETMAP_API_TOKEN="full-token")
    return c


def add_leasefile(tmp_path, text, name="lan"):
    from app import sources
    f = tmp_path / f"{name}.leases"
    f.write_text(text)
    return sources.create_instance("leasefile", name, {"path": str(f)})["id"]


def test_a_lease_file_alone_fills_the_map_and_catches_a_mac_mismatch(app, tmp_path):
    """The plan's "done when": only a dnsmasq file, and still an address map
    and a mac-mismatch."""
    from app import db, discovery
    far = 4102444800                                   # 2100: never expires in this test
    iid = add_leasefile(tmp_path, f"""\
{far} aa:bb:cc:00:00:01 192.168.10.10 nas *
{far} aa:bb:cc:00:00:99 192.168.10.11 impostor *
{far} aa:bb:cc:00:00:05 192.168.10.50 laptop *
{far} aa:bb:cc:00:00:07 192.168.10.60 guest *
""")
    nas = db.create_entry({"name": "NAS", "ip": "192.168.10.10", "mac": "AA:BB:CC:00:00:01"})
    cam = db.create_entry({"name": "Camera", "ip": "192.168.10.11", "mac": "aa:bb:cc:00:00:02"})
    lap = db.create_entry({"name": "Laptop", "ip": "192.168.10.40", "mac": "aa:bb:cc:00:00:05"})
    db.create_entry({"name": "Service on NAS", "ip": "192.168.10.11"})      # no MAC: not judged
    r = discovery.scan(iid)
    assert r["error"] is None and r["host"]["format"] == "dnsmasq"
    by = {f["type"]: f for f in r["findings"]}
    assert set(by) == {"mac-mismatch", "ip-moved"}
    assert by["mac-mismatch"]["entry"]["id"] == cam["id"]
    assert "aa:bb:cc:00:00:99" in by["mac-mismatch"]["label"]
    assert by["ip-moved"]["entry"]["id"] == lap["id"]
    assert by["ip-moved"]["suggest"] == {"ip": "192.168.10.50"}
    assert r["counts"]["addresses"] == 4 and r["counts"]["matched"] == 1
    assert {s["fact"] for s in db.sightings_for(nas["id"])} == {"lease"}
    untracked = {p["ip"] for p in db.presence()}
    assert {"192.168.10.50", "192.168.10.60"} <= untracked and "192.168.10.10" not in untracked


def test_an_ignored_finding_stays_ignored(app, tmp_path):
    from app import db, discovery
    iid = add_leasefile(tmp_path, "4102444800 aa:bb:cc:00:00:99 192.168.10.11 x *\n")
    cam = db.create_entry({"name": "Camera", "ip": "192.168.10.11", "mac": "aa:bb:cc:00:00:02"})
    db.add_ignore(f"leasefile:leasemac:{cam['id']}", "leasefile")
    r = discovery.scan(iid)
    assert r["findings"] == [] and r["counts"]["ignored"] == 1


def test_two_lease_sources_shadow_each_others_moves(app, tmp_path):
    """Two segments, two DHCP servers: one sees the laptop elsewhere, the
    other sees it where the inventory says. The move is not news."""
    from app import db, discovery
    lap = db.create_entry({"name": "Laptop", "ip": "192.168.10.40", "mac": "aa:bb:cc:00:00:05"})
    a = add_leasefile(tmp_path, "4102444800 aa:bb:cc:00:00:05 10.0.0.9 laptop *\n", "guest")
    b = add_leasefile(tmp_path, "4102444800 aa:bb:cc:00:00:05 192.168.10.40 laptop *\n", "lan")
    assert discovery.scan(b)["findings"] == []
    r = discovery.scan(a)
    assert r["findings"] == [] and r["counts"]["shadowed"] == 1
    assert lap["id"]


# ---- SNMP ---------------------------------------------------------------------------------------
def test_ber_known_answers():
    from app.sources import snmparp
    assert snmparp.encode_oid("1.3.6.1.2.1.1.1.0") == bytes.fromhex("06082b06010201010100")
    assert snmparp.encode_oid("1.3.6.1.4.1.311") == bytes.fromhex("06072b060104018237")
    assert snmparp.decode_oid(bytes.fromhex("2b06010201010100")) == "1.3.6.1.2.1.1.1.0"
    assert snmparp._int(0) == b"\x02\x01\x00" and snmparp._int(128) == b"\x02\x02\x00\x80"
    assert snmparp._len(200) == b"\x81\xc8"


def test_the_module_can_only_read():
    """Read-only by construction: GetBulk is the one request it can build."""
    import inspect
    from app.sources import snmparp
    src = inspect.getsource(snmparp)
    assert "0xa3" not in src.lower()                     # SetRequest's PDU tag
    assert snmparp.GET_BULK == 0xA5
    req = snmparp.bulk_request("public", 7, "1.3.6.1.2.1.1.1")
    assert req[req.index(b"public") + 6] == 0xA5          # the PDU that follows


class Agent:
    """A fake SNMP v2c agent: answers GetBulk from a table of oid -> (tag,
    value), for one community only - silence otherwise, as a real one does."""

    def __init__(self, table: dict, community="public"):
        from app.sources import snmparp as s
        self.s, self.community, self.requests = s, community, 0
        key = lambda o: tuple(int(x) for x in o.split("."))  # noqa: E731
        self.oids = sorted(table, key=key)
        self.key, self.table = key, table
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        s = self.s
        while True:
            try:
                data, peer = self.sock.recvfrom(65535)
            except OSError:
                return
            _, msg, _ = s._read(data, 0)
            parts = s._items(msg)
            if parts[1][1].decode() != self.community or parts[2][0] != s.GET_BULK:
                continue
            self.requests += 1
            pdu = s._items(parts[2][1])
            req_id, reps = pdu[0][1], int.from_bytes(pdu[2][1], "big")
            (_, oid_b), _ = s._items(s._items(pdu[3][1])[0][1])
            start = self.key(s.decode_oid(oid_b))
            after = [o for o in self.oids if self.key(o) > start][:reps]
            binds = b"".join(s._tlv(0x30, s.encode_oid(o) + s._tlv(*self.table[o]))
                             for o in after)
            if len(after) < reps:
                binds += s._tlv(0x30, s.encode_oid("1.3.6.1.9.9.9") + s._tlv(0x82, b""))
            resp = s._tlv(s.RESPONSE, s._tlv(0x02, req_id) + s._int(0) + s._int(0)
                          + s._tlv(0x30, binds))
            self.sock.sendto(s._tlv(0x30, s._int(1) + s._tlv(0x04, parts[1][1]) + resp), peer)

    def close(self):
        self.sock.close()


def arp_table(rows, table="media"):
    """rows: (ifIndex, ip, mac, type) -> oid table for either MIB table."""
    t = {"1.3.6.1.2.1.1.1.0": (0x04, b"Test router 1.0")}
    for if_, ip, mac, typ in rows:
        m = bytes.fromhex(mac.replace(":", ""))
        if table == "media":
            idx = f"{if_}.{ip}"
            t[f"1.3.6.1.2.1.4.22.1.2.{idx}"] = (0x04, m)
            t[f"1.3.6.1.2.1.4.22.1.4.{idx}"] = (0x02, bytes([typ]))
        else:
            idx = f"{if_}.1.4.{ip}"
            t[f"1.3.6.1.2.1.4.35.1.4.{idx}"] = (0x04, m)
            t[f"1.3.6.1.2.1.4.35.1.6.{idx}"] = (0x02, bytes([typ]))
    return t


def cfg_for(agent, community="public"):
    return {"host": "127.0.0.1", "port": agent.port, "community": community, "timeout": 0.5,
            "_id": "snmparp", "_key": "snmparp"}


def test_the_arp_table_is_read_with_getbulk():
    from app.sources import snmparp
    rows = [(2, f"192.168.10.{i}", f"aa:bb:cc:00:01:{i:02x}", 3) for i in range(1, 60)]
    rows.append((2, "192.168.10.200", "aa:bb:cc:00:02:00", 2))          # invalid: skipped
    ag = Agent(arp_table(rows))
    try:
        got = {r["ip"]: r["mac"] for r in snmparp.neighbours(cfg_for(ag))}
        assert len(got) == 59 and got["192.168.10.7"] == "aa:bb:cc:00:01:07"
        assert "192.168.10.200" not in got
        assert ag.requests > 3                                          # it paged
        assert snmparp.test(cfg_for(ag)) == {"ok": True, "error": None, "system": "Test router 1.0"}
    finally:
        ag.close()


def test_ip_net_to_physical_when_the_old_table_is_empty():
    from app.sources import snmparp
    ag = Agent(arp_table([(3, "10.0.0.5", "aa:bb:cc:00:03:05", 3)], table="phys"))
    try:
        assert snmparp.neighbours(cfg_for(ag)) == [
            {"ip": "10.0.0.5", "mac": "aa:bb:cc:00:03:05", "label": "", "detail": "ARP"}]
    finally:
        ag.close()


def test_a_wrong_community_is_no_answer():
    from app.sources import snmparp
    ag = Agent(arp_table([]))
    try:
        r = snmparp.test(cfg_for(ag, "wrong"))
        assert r["ok"] is False and "no answer" in r["error"] and "community" in r["error"]
    finally:
        ag.close()


def test_an_snmp_source_reports_like_any_leases_source(app, monkeypatch):
    from app import db, discovery, sources
    ag = Agent(arp_table([(2, "192.168.10.11", "aa:bb:cc:00:00:99", 3)]))
    try:
        cam = db.create_entry({"name": "Camera", "ip": "192.168.10.11", "mac": "aa:bb:cc:00:00:02"})
        iid = sources.create_instance("snmparp", "", {"host": "127.0.0.1", "port": ag.port,
                                                      "community": "public", "timeout": 0.5})["id"]
        r = discovery.scan(iid)
        assert r["error"] is None
        assert [(f["type"], f["entry"]["id"]) for f in r["findings"]] == [("mac-mismatch", cam["id"])]
        assert "ARP" in r["findings"][0]["detail"]
    finally:
        ag.close()


def test_a_lease_file_path_must_be_a_regular_file():
    from app.sources import leasefile
    import pytest
    with pytest.raises(ValueError, match="not a regular file"):
        leasefile.read({"path": "/dev/zero", "format": "dnsmasq"})
