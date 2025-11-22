# firewall.py
"""
WinDivert + Scapy user-space firewall for Windows (NetGuard Lab)
- Requires: pydivert, scapy, flask
- Run this script as Administrator.
- Places logs in ./logs/netguard.log
- Exposes a small control API on http://127.0.0.1:5001 for Streamlit.

Run:
    python firewall.py   (in Administrator PowerShell)
"""

import threading
import time
import json
import os
from datetime import datetime
from collections import defaultdict

from pydivert import WinDivert
from scapy.all import IP, TCP, raw
from flask import Flask, request, jsonify

LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'netguard.log')

FILTER = "ip"  # capture all IP traffic

app = Flask(__name__)

# ------------------------ LOGGING ------------------------

class FileLogger:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def info(self, obj):
        line = json.dumps(obj)
        with self.lock:
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write(line + "\n")
        print(line)

LOG = FileLogger(LOG_FILE)

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# ------------------------ FIREWALL ------------------------

class Firewall(threading.Thread):
    def __init__(self, filter_expr=FILTER):
        super().__init__(daemon=True)
        self.filter_expr = filter_expr
        self._stop = threading.Event()
        self.blocklist = {}  # ip -> expiry_ts
        self.lock = threading.Lock()
        self.syn_count = defaultdict(list)   # src -> timestamps
        self.syn_threshold = 50              # SYN per 60s

    def run(self):
        LOG.info({"ts": now_iso(), "msg": "firewall_start", "filter": self.filter_expr})
        try:
            with WinDivert(self.filter_expr) as w:
                while not self._stop.is_set():
                    try:
                        packet = w.recv()
                    except Exception:
                        continue

                    raw_bytes = bytes(packet.raw)

                    try:
                        pkt = IP(raw_bytes)
                    except Exception:
                        w.send(packet)
                        continue

                    action, reason = self._decide(pkt)
                    self._log(pkt, action, reason)

                    if action == "accept":
                        w.send(packet)
                    elif action in ("drop", "drop_block"):
                        pass  # drop
                        if action == "drop_block":
                            with self.lock:
                                self.blocklist[pkt.src] = time.time() + 60

                    self._cleanup_blocks()

        except Exception as e:
            LOG.info({"ts": now_iso(), "error": str(e)})

    def stop(self):
        self._stop.set()

    # ------------------ decision logic ------------------

    def _decide(self, pkt):
        src = pkt.src
        now = time.time()

        # temporary block
        with self.lock:
            if src in self.blocklist and self.blocklist[src] > now:
                return "drop", "temp_block"

        # SYN detection
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]

            # record SYNs
            if tcp.flags & 0x02:
                self._record_syn(src, now)
                if self._is_syn_flooding(src):
                    return "drop_block", "syn_threshold"

            # Example rule: block SYN to port 80
            if tcp.flags & 0x02 and tcp.dport == 80:
                return "drop", "syn_to_80"

        return "accept", None

    # ------------------ SYN tracking ------------------

    def _record_syn(self, src, ts):
        lst = self.syn_count[src]
        lst.append(ts)
        cutoff = ts - 60
        while lst and lst[0] < cutoff:
            lst.pop(0)

    def _is_syn_flooding(self, src):
        return len(self.syn_count[src]) > self.syn_threshold

    # ------------------ blocklist maintenance ------------------

    def _cleanup_blocks(self):
        now = time.time()
        with self.lock:
            expired = [ip for ip, exp in self.blocklist.items() if exp <= now]
            for ip in expired:
                del self.blocklist[ip]
                LOG.info({"ts": now_iso(), "msg": "block_expired", "ip": ip})

    # ------------------ logging ------------------

    def _log(self, pkt, action, reason):
        LOG.info({
            "ts": now_iso(),
            "src": pkt.src,
            "dst": pkt.dst,
            "proto": pkt.proto,
            "action": action,
            "reason": reason
        })

    # ------------------ API helpers ------------------

    def add_block(self, ip, seconds=60):
        with self.lock:
            self.blocklist[ip] = time.time() + seconds
        LOG.info({"ts": now_iso(), "msg": "block_added", "ip": ip})

    def remove_block(self, ip):
        with self.lock:
            if ip in self.blocklist:
                del self.blocklist[ip]
        LOG.info({"ts": now_iso(), "msg": "block_removed", "ip": ip})

    def status(self):
        with self.lock:
            return {"blocklist": self.blocklist.copy()}


FW = Firewall()

# ------------------------ API ROUTES ------------------------

@app.route("/block", methods=["POST"])
def api_block():
    data = request.get_json() or {}
    ip = data.get("ip")
    secs = int(data.get("seconds", 60))
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    FW.add_block(ip, secs)
    return jsonify({"ok": True})

@app.route("/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    FW.remove_block(ip)
    return jsonify({"ok": True})

@app.route("/status")
def api_status():
    return jsonify({"running": True, "status": FW.status()})


if __name__ == "__main__":
    FW.start()

    api_t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5001, debug=False),
        daemon=True
    )
    api_t.start()

    print("Firewall running at http://127.0.0.1:5001")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        FW.stop()
        print("Shutting down...")
