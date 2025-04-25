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

INPUT_DIR = './nmap_xml/'
OUTPUT_ALL_HOSTS = './output/all_hosts.csv'
OUTPUT_DETAILED = './output/port_detailed_report.csv'
os.makedirs(os.path.dirname(OUTPUT_ALL_HOSTS), exist_ok=True)

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
    'hostnames': set(),
    'os': 'unknown',
    'ip': '',
    'file': '',
    'timestamp': '',
    'ports': []
})

port_detailed_data = []

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

                hostnames = []
                for hn in host.findall("hostnames/hostname"):
                    hostnames.append(hn.attrib.get('name'))

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

                    proto = port.attrib.get('protocol')
                    portid = int(port.attrib.get('portid'))
                    service_el = port.find('service')
                    service_name = service_el.attrib.get('name') if service_el is not None else 'unknown'
                    product = service_el.attrib.get('product') if service_el is not None and 'product' in service_el.attrib else ''
                    service_fp = service_el.attrib.get('ostype') if service_el is not None and 'ostype' in service_el.attrib else ''

                    category = get_service_category(portid, service_name)

                    # Parse NSE script output
                    script_id = ''
                    script_output = ''
                    for script in port.findall('script'):
                        script_id = script.attrib.get('id', '')
                        script_output = script.attrib.get('output', '')

                    port_detailed_data.append([
                        portid,
                        address,
                        ';'.join(hostnames) if hostnames else 'N/A',
                        os_guess,
                        proto,
                        service_name,
                        category,
                        product,
                        service_fp,
                        script_id,
                        script_output,
                        filename,
                        ''  # Notes
                    ])

                    host_data[address]['hostnames'].update(hostnames)
                    host_data[address]['os'] = os_guess
                    host_data[address]['ip'] = address
                    host_data[address]['file'] = filename
                    host_data[address]['timestamp'] = scan_time
                    host_data[address]['ports'].append((portid, proto, service_name, category, product, service_fp, script_id, script_output))

        except ET.ParseError:
            print(f"[!] Failed to parse {filename}")

# Sort port-detailed data by Port then IP
port_detailed_data.sort(key=lambda x: (x[0], x[1]))

# Write port-detailed CSV
with open(OUTPUT_DETAILED, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Port', 'IP', 'Host', 'OS', 'Protocol', 'Service', 'Category', 'Product', 'Service FP', 'NSE Script ID', 'NSE Script Output', 'Source File', 'Notes'])
    writer.writerows(port_detailed_data)

# Write all-hosts summary CSV
with open(OUTPUT_ALL_HOSTS, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['IP', 'Hostnames', 'OS', 'Port Count', 'Ports', 'Protocols', 'Services', 'Categories', 'Products', 'Service FPs', 'NSE Script IDs', 'NSE Script Outputs', 'Source File', 'Timestamp'])
    for ip, data in host_data.items():
        ports = [str(p[0]) for p in data['ports']]
        protocols = [p[1] for p in data['ports']]
        services = [p[2] for p in data['ports']]
        categories = [p[3] for p in data['ports']]
        products = [p[4] for p in data['ports']]
        service_fps = [p[5] for p in data['ports']]
        script_ids = [p[6] for p in data['ports']]
        script_outputs = [p[7] for p in data['ports']]
        writer.writerow([
            data['ip'],
            ';'.join(data['hostnames']) if data['hostnames'] else 'N/A',
            data['os'],
            len(data['ports']),
            ';'.join(ports),
            ';'.join(protocols),
            ';'.join(services),
            ';'.join(categories),
            ';'.join(products),
            ';'.join(service_fps),
            ';'.join(script_ids),
            ';'.join(script_outputs),
            data['file'],
            data['timestamp']
        ])

print(f"[+] Host summary written to {OUTPUT_ALL_HOSTS}")
print(f"[+] Port details written to {OUTPUT_DETAILED}")
