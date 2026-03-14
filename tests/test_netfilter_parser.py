import time
from datetime import datetime
from defensewatch.parsers.netfilter import parse_netfilter_line


def test_valid_syn_syslog_timestamp():
    line = (
        'Mar 14 10:23:45 myhost kernel: [12345.678] DWSYN:IN=eth0 OUT= '
        'MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 '
        'SRC=91.99.105.252 DST=10.0.0.1 LEN=44 TOS=0x00 PREC=0x00 TTL=64 '
        'ID=54321 DF PROTO=TCP SPT=45678 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0'
    )
    ev = parse_netfilter_line(line)
    assert ev is not None
    assert ev.source_ip == "91.99.105.252"
    assert ev.dest_port == 22
    assert ev.timestamp > 0


def test_valid_syn_iso_timestamp():
    line = (
        '2026-03-14T10:23:45.123456+01:00 myhost kernel: DWSYN:IN=eth0 OUT= '
        'SRC=192.168.1.100 DST=10.0.0.1 LEN=44 TOS=0x00 PREC=0x00 TTL=64 '
        'ID=54321 DF PROTO=TCP SPT=45678 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0'
    )
    ev = parse_netfilter_line(line)
    assert ev is not None
    assert ev.source_ip == "192.168.1.100"
    assert ev.dest_port == 443


def test_syn_ack_rejected():
    """SYN-ACK lines (responses from our services) should be ignored."""
    line = (
        'Mar 14 10:23:45 myhost kernel: DWSYN:IN=eth0 OUT= '
        'SRC=10.0.0.1 DST=192.168.1.100 LEN=44 TOS=0x00 PREC=0x00 TTL=64 '
        'ID=54321 DF PROTO=TCP SPT=22 DPT=45678 WINDOW=1024 RES=0x00 SYN ACK URGP=0'
    )
    assert parse_netfilter_line(line) is None


def test_no_prefix_rejected():
    """Lines without DWSYN: prefix should be ignored."""
    line = (
        'Mar 14 10:23:45 myhost kernel: [12345.678] IN=eth0 OUT= '
        'SRC=91.99.105.252 DST=10.0.0.1 LEN=44 PROTO=TCP SPT=45678 DPT=22 SYN URGP=0'
    )
    assert parse_netfilter_line(line) is None


def test_udp_rejected():
    """UDP packets should be ignored."""
    line = (
        'Mar 14 10:23:45 myhost kernel: DWSYN:IN=eth0 OUT= '
        'SRC=91.99.105.252 DST=10.0.0.1 LEN=44 PROTO=UDP SPT=45678 DPT=53'
    )
    assert parse_netfilter_line(line) is None


def test_missing_dpt_rejected():
    line = (
        'Mar 14 10:23:45 myhost kernel: DWSYN:IN=eth0 OUT= '
        'SRC=91.99.105.252 DST=10.0.0.1 LEN=44 PROTO=TCP SPT=45678 SYN URGP=0'
    )
    assert parse_netfilter_line(line) is None


def test_missing_src_rejected():
    line = (
        'Mar 14 10:23:45 myhost kernel: DWSYN:IN=eth0 OUT= '
        'DST=10.0.0.1 LEN=44 PROTO=TCP SPT=45678 DPT=22 SYN URGP=0'
    )
    assert parse_netfilter_line(line) is None


def test_multiple_ports_different_ips():
    """Ensure different SRC addresses produce different events."""
    base = (
        'Mar 14 10:23:45 myhost kernel: DWSYN:IN=eth0 OUT= '
        'SRC={ip} DST=10.0.0.1 LEN=44 PROTO=TCP SPT=45678 DPT={port} '
        'WINDOW=1024 RES=0x00 SYN URGP=0'
    )
    ev1 = parse_netfilter_line(base.format(ip="1.2.3.4", port=22))
    ev2 = parse_netfilter_line(base.format(ip="5.6.7.8", port=80))
    assert ev1.source_ip == "1.2.3.4"
    assert ev1.dest_port == 22
    assert ev2.source_ip == "5.6.7.8"
    assert ev2.dest_port == 80


def test_empty_and_garbage():
    assert parse_netfilter_line("") is None
    assert parse_netfilter_line("some random log line") is None
    assert parse_netfilter_line("DWSYN:") is None
