from pydivert import WinDivert
from scapy.all import IP, TCP

with WinDivert("tcp") as w:
    print("Listening for TCP packets... (Ctrl+C to stop)")
    count = 0
    for packet in w:
        raw_bytes = bytes(packet.raw)   # ← FIX

        try:
            p = IP(raw_bytes)
        except Exception as e:
            print("Failed to parse packet:", e)
            w.send(packet)
            continue

        print(f"{p.src} -> {p.dst} (TCP)")

        w.send(packet)    # forward packet
        count += 1
        if count >= 5:
            break
