import os
import xml.etree.ElementTree as ET
import csv
from collections import defaultdict
from datetime import datetime

# Define extended service-port mappings
SERVICE_CATEGORIES = {
    'web': [80, 8080, 8000, 443, 8443],
    'ssh': [22],
    'ftp': [21],
    'rdp': [3389],
    'dns': [53],
    'smtp': [25, 465, 587],
    'pop3': [110, 995],
    'imap': [143, 993],
    'db': [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    'file-sharing': [139, 445],
    'vpn': [1194, 500]
}

INPUT_DIR = './nmap_xml/'  # Directory with .xml files
OUTPUT_FILE = './output/all_hosts.csv'
OUTPUT_PORT_VIEW = './output/segregated_by_port.csv'
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# Categorize port to service bucket or use service name fallback
def get_service_category(port, service_name):
    for category, ports in SERVICE_CATEGORIES.items():
        if port in ports:
            return category
    if service_name:
        name = service_name.lower()
        if 'http' in name or 'web' in name:
            return 'web'
        elif 'ssh' in name:
            return 'ssh'
        elif 'ftp' in name:
            return 'ftp'
        elif 'rdp' in name:
            return 'rdp'
        elif 'smtp' in name or 'mail' in name:
            return 'smtp'
        elif 'pop3' in name:
            return 'pop3'
        elif 'imap' in name:
            return 'imap'
        elif 'mysql' in name or 'mssql' in name or 'postgres' in name or 'mongo' in name or 'redis' in name:
            return 'db'
        elif 'smb' in name or 'netbios' in name:
            return 'file-sharing'
        elif 'vpn' in name:
            return 'vpn'
    return 'misc'

host_data = defaultdict(lambda: {
    'ports': [],
    'hostnames': set(),
    'os': 'unknown',
    'ip': '',
    'file': '',
    'timestamp': ''
})

port_view_data = []

for filename in os.listdir(INPUT_DIR):
    if filename.endswith('.xml'):
        filepath = os.path.join(INPUT_DIR, filename)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            scan_time = datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()

            for host in root.findall('host'):
                address_el = host.find('address')
                address = address_el.attrib.get('addr') if address_el is not None else 'unknown'

                hostnames = set()
                for hn in host.findall("hostnames/hostname"):
                    hostnames.add(hn.attrib.get('name'))

                os_guess = 'unknown'
                os_el = host.find("os")
                if os_el is not None:
                    best_os = os_el.find("osmatch")
                    if best_os is not None:
                        os_guess = best_os.attrib.get('name')

                ports = host.find('ports')
                if ports is None:
                    continue

                for port in ports.findall('port'):
                    state = port.find('state').attrib.get('state')
                    if state != 'open':
                        continue

                    portid = int(port.attrib.get('portid'))
                    service_el = port.find('service')
                    service_name = service_el.attrib.get('name') if service_el is not None else 'unknown'

                    category = get_service_category(portid, service_name)

                    host_data[address]['ports'].append((portid, service_name, category))
                    host_data[address]['hostnames'].update(hostnames)
                    host_data[address]['os'] = os_guess
                    host_data[address]['ip'] = address
                    host_data[address]['file'] = filename
                    host_data[address]['timestamp'] = scan_time

                    # Add to port-segregated view
                    port_view_data.append([
                        portid,
                        address,
                        ';'.join(hostnames) if hostnames else 'N/A',
                        os_guess,
                        service_name,
                        category,
                        filename
                    ])

        except ET.ParseError:
            print(f"[!] Failed to parse {filename}")

# Sort the port-segregated view by port number, then IP
port_view_data.sort(key=lambda x: (x[0], x[1]))

# Write to the standard host-centric CSV
with open(OUTPUT_FILE, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['IP', 'Hostnames', 'OS', 'Port Count', 'Ports', 'Services', 'Categories', 'Source File', 'Timestamp'])
    for ip, data in host_data.items():
        ports = [str(p[0]) for p in data['ports']]
        services = [p[1] for p in data['ports']]
        categories = [p[2] for p in data['ports']]
        writer.writerow([
            data['ip'],
            ';'.join(data['hostnames']) if data['hostnames'] else 'N/A',
            data['os'],
            len(data['ports']),
            ';'.join(ports),
            ';'.join(services),
            ';'.join(categories),
            data['file'],
            data['timestamp']
        ])

# Write port-segregated view CSV
with open(OUTPUT_PORT_VIEW, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Port', 'IP', 'Hostnames', 'OS', 'Service', 'Category', 'Source File'])
    writer.writerows(port_view_data)

print(f"[+] Host summary written to {OUTPUT_FILE}")
print(f"[+] Port view written to {OUTPUT_PORT_VIEW}")

