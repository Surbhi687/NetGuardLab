# streamlit_app.py
"""
Streamlit UI for NetGuard Lab (Windows).
Run:
    streamlit run streamlit_app.py
Firewall must already be running:
    python firewall.py  (admin terminal)
"""

import streamlit as st
import requests
import json
import time

from playbooks import arp_scan, syn_probe, banner_grab, http_abuse_sim

API = "http://127.0.0.1:5001"

st.set_page_config(page_title="NetGuard Lab (Windows)")
st.title("NetGuard Lab — Windows Firewall + Playbooks")


# -------------------- FIREWALL CONTROLS --------------------

st.header("Firewall Controls")

if st.button("Check Firewall Status"):
    try:
        st.json(requests.get(API + "/status").json())
    except Exception as e:
        st.error(f"Error: {e}")

ip = st.text_input("IP to block/unblock")

sec = st.number_input("Block duration (seconds)", min_value=1, value=60)

if st.button("Add Block"):
    if not ip:
        st.error("Enter IP")
    else:
        r = requests.post(API + "/block", json={"ip": ip, "seconds": sec})
        st.write(r.json())

if st.button("Remove Block"):
    if not ip:
        st.error("Enter IP")
    else:
        r = requests.post(API + "/unblock", json={"ip": ip})
        st.write(r.json())


# -------------------- PLAYBOOKS --------------------

st.header("Playbooks (Safe)")

# ARP scan
if st.button("Run ARP Scan"):
    cidr = st.text_input("Network CIDR", "172.30.48.1")
    res = arp_scan(cidr)
    st.json(res)

# SYN probe
target = st.text_input("SYN probe target", "192.168.1.1")
if st.button("Run SYN Probe"):
    st.json(syn_probe(target))

# Banner grab
banner_host = st.text_input("Banner host", "192.168.1.1")
banner_port = st.number_input("Banner port", 1, 65535, 22)
if st.button("Grab Banner"):
    st.json(banner_grab(banner_host, banner_port))

# HTTP sim
http_url = st.text_input("HTTP test URL", "http://example.com")
if st.button("Run HTTP Sim"):
    st.json(http_abuse_sim(http_url))


# -------------------- LOG VIEWER --------------------

st.header("Logs")

if st.button("Show Last 10 Log Lines"):
    try:
        with open("logs/netguard.log", "r", encoding="utf-8") as f:
            lines = f.readlines()[-10:]
        st.text("".join(lines))
    except Exception as e:
        st.error(f"Error reading log file: {e}")
