# playbooks.py
"""
Safe reconnaissance playbooks for NetGuard Lab (Windows)
Requires Scapy and administrator privileges for ARP/SYN.

These functions DO NOT perform attacks — only safe scans for testing.
"""

import time
import socket
from scapy.all import ARP, Ether, srp, IP, TCP, sr1


def arp_scan(network="192.168.1.0/24", timeout=2):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    ans, _ = srp(pkt, timeout=timeout, retry=0)
    results = [(r.psrc, r.hwsrc) for s, r in ans]
    return {
        "ts": time.time(),
        "type": "arp_scan",
        "network": network,
        "results": results
    }


def syn_probe(target, ports=None, timeout=1):
    ports = ports or [22, 80, 443, 8080]
    results = {}

    for p in ports:
        pkt = IP(dst=target) / TCP(dport=p, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            results[p] = "filtered/closed"
        elif resp.haslayer(TCP) and resp[TCP].flags & 0x12:
            results[p] = "open"
        else:
            results[p] = "closed"

    return {
        "ts": time.time(),
        "type": "syn_probe",
        "target": target,
        "results": results
    }


def banner_grab(host, port, timeout=2):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        data = s.recv(1024)
        s.close()
        return {
            "ts": time.time(),
            "type": "banner",
            "host": host,
            "port": port,
            "banner": data.decode(errors="replace")
        }
    except Exception as e:
        return {
            "ts": time.time(),
            "type": "banner",
            "host": host,
            "port": port,
            "error": str(e)
        }



def http_abuse_sim(url):
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            body = r.read(200)
            return {
                "ts": time.time(),
                "type": "http_sim",
                "url": url,
                "status": r.status,
                "body_preview": body.decode(errors="replace")
            }
    except Exception as e:
        return {
            "ts": time.time(),
            "type": "http_sim",
            "url": url,
            "error": str(e)
        }
