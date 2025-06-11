import threading
import geoip2.database
from flask import Flask, jsonify, render_template, request
from scapy.all import sniff, IP, TCP
import requests
import json
import os
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)

GEOIP_DB_PATH = "GeoLite2-City.mmdb"
geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

traffic_data = []
source_countries = {}
destination_countries = {}
processed_packets = set()

TRAFFIC_DATA_FILE = 'traffic_data.json'
SOURCE_COUNTRIES_FILE = 'source_countries.json'
DESTINATION_COUNTRIES_FILE = 'destination_countries.json'

PORT_TO_PROTOCOL = {
    20: "FTP (Data Transfer)", 21: "FTP (Control)", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 1433: "MSSQL", 6379: "Redis",
    5432: "PostgreSQL", 1521: "Oracle DB", 3389: "RDP",
}

def get_global_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        return response.json().get('ip')
    except requests.RequestException:
        return None

global_ip = get_global_ip()

def is_local_ip(ip):
    local_patterns = [
        r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\.", r"^127\.",
        r"^::1$", r"^fc00:", r"^fe80:"
    ]
    return any(re.match(pattern, ip) for pattern in local_patterns)

def get_location(ip_address):
    try:
        response = geoip_reader.city(ip_address)
        return {
            "ip": ip_address,
            "city": response.city.name or "Unknown",
            "country": response.country.name or "Unknown",
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
    except Exception:
        return {
            "ip": ip_address,
            "city": "Unknown",
            "country": "Unknown",
            "latitude": None,
            "longitude": None,
        }

def get_protocol(port):
    return PORT_TO_PROTOCOL.get(port, f"Unknown (Port {port})")

def update_source_countries(source):
    country = source.get("country", "Unknown")
    if country != "Unknown":
        source_countries[country] = source_countries.get(country, 0) + 1

def update_destination_countries(destination):
    country = destination.get("country", "Unknown")
    if country != "Unknown":
        destination_countries[country] = destination_countries.get(country, 0) + 1

def process_packet(packet):
    if IP in packet and TCP in packet:
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        src_ip = packet[IP].src

        if is_local_ip(dest_ip):
            return

        if is_local_ip(src_ip) and global_ip:
            src_ip = global_ip
        elif not src_ip:
            return

        packet_key = f"{src_ip}:{packet[TCP].sport}->{dest_ip}:{dest_port}"
        if packet_key in processed_packets:
            return
        processed_packets.add(packet_key)

        src_info = get_location(src_ip)
        dest_info = get_location(dest_ip)
        protocol = get_protocol(dest_port)

        update_source_countries(src_info)
        update_destination_countries(dest_info)

        traffic_data.append({
            "source": src_info,
            "destination": dest_info,
            "type": protocol,
            "timestamp": int(packet.time),
            "sent": 0
        })

        if len(traffic_data) > 1000:
            traffic_data.pop(0)

def save_data():
    with open(TRAFFIC_DATA_FILE, 'w') as f:
        json.dump(traffic_data, f, indent=4)
    with open(SOURCE_COUNTRIES_FILE, 'w') as f:
        json.dump(source_countries, f, indent=4)
    with open(DESTINATION_COUNTRIES_FILE, 'w') as f:
        json.dump(destination_countries, f, indent=4)

def load_data():
    global traffic_data, source_countries, destination_countries
    if os.path.exists(TRAFFIC_DATA_FILE):
        with open(TRAFFIC_DATA_FILE, 'r') as f:
            traffic_data = json.load(f)
    if os.path.exists(SOURCE_COUNTRIES_FILE):
        with open(SOURCE_COUNTRIES_FILE, 'r') as f:
            source_countries = json.load(f)
    if os.path.exists(DESTINATION_COUNTRIES_FILE):
        with open(DESTINATION_COUNTRIES_FILE, 'r') as f:
            destination_countries = json.load(f)

def start_packet_sniffer():
    filter_str = "tcp"
    if global_ip:
        filter_str += f" and not src host {global_ip}"
    sniff(filter=filter_str, prn=process_packet, store=False)

def save_periodically():
    while True:
        threading.Event().wait(5)
        save_data()

threading.Thread(target=start_packet_sniffer, daemon=True).start()
threading.Thread(target=save_periodically, daemon=True).start()

@app.route('/traffic', methods=['GET'])
def traffic_api():
    data_to_send = [entry for entry in traffic_data if entry["sent"] == 0]
    return jsonify(data_to_send)

@app.route('/source_stats', methods=['GET'])
def source_stats_api():
    sorted_sources = dict(sorted(source_countries.items(), key=lambda item: item[1], reverse=True))
    return jsonify({"sources": sorted_sources})

@app.route('/destination_stats', methods=['GET'])
def destination_stats_api():
    sorted_destinations = dict(sorted(destination_countries.items(), key=lambda item: item[1], reverse=True))
    return jsonify({"destinations": sorted_destinations})

@app.route('/mark_sent', methods=['POST'])
def mark_sent_api():
    ids_to_mark = request.json.get('ids', [])
    for entry in traffic_data:
        if entry['timestamp'] in ids_to_mark:
            entry['sent'] = 1
    save_data()
    return jsonify({"status": "success"})

@app.route('/')
def index():
    return render_template("index.html")

load_data()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)

