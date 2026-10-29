"""Run a small authorized lab scan, or report on an existing Nmap XML file."""
import argparse
import ipaddress
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def lab_target(value):
    address = ipaddress.ip_address(value)
    allowed = (ipaddress.ip_network('10.0.0.0/8'),
               ipaddress.ip_network('172.16.0.0/12'),
               ipaddress.ip_network('192.168.0.0/16'))
    if address.version != 4 or not any(address in net for net in allowed):
        raise ValueError('Use one RFC1918 IPv4 address in your authorized lab.')
    return str(address)


def parse_scan(path):
    root = ET.parse(path).getroot()
    if root.tag != 'nmaprun':
        raise ValueError('Expected an Nmap XML document.')
    hosts = []
    for host in root.findall('host'):
        address = host.find("address[@addrtype='ipv4']")
        status = host.find('status')
        ports = []
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            service = port.find('service')
            ports.append({'port': int(port.get('portid')),
                          'protocol': port.get('protocol'),
                          'service': service.get('name', 'unknown') if service is not None else 'unknown',
                          'product': service.get('product', '') if service is not None else ''})
        hosts.append({'address': address.get('addr') if address is not None else 'unknown',
                      'status': status.get('state') if status is not None else 'unknown',
                      'open_ports': ports})
    return hosts


def markdown(hosts, evidence):
    lines = ['# Network service inventory', '', f'Evidence: **{evidence}**', '',
             'Open ports are observations, not confirmed vulnerabilities.', '',
             '| Host | State | Port | Service |', '| --- | --- | --- | --- |']
    for host in hosts:
        for port in host['open_ports']:
            service = port['service'].replace('|', '\\|').replace('\n', ' ')
            lines.append(f"| {host['address']} | {host['status']} | {port['port']}/{port['protocol']} | {service} |")
        if not host['open_ports']:
            lines.append(f"| {host['address']} | {host['status']} | None reported | |")
    lines += ['', '## Follow-up', '',
              '- Confirm each exposed service is expected in the approved scope.',
              '- Compare versions with vendor advisories before claiming a vulnerability.',
              '- Restrict unnecessary services and repeat the same scan to verify changes.',
              '- Record target ownership, scan time, and lab screenshots separately.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--xml', type=Path, help='Read existing XML; no scan is performed')
    source.add_argument('--scan', help='One authorized RFC1918 IPv4 target')
    parser.add_argument('--authorized', action='store_true', help='Confirm target permission')
    parser.add_argument('--out', type=Path, default=Path('reports'))
    parser.add_argument('--synthetic', action='store_true', help='Label fixture results as synthetic')
    args = parser.parse_args()
    if args.synthetic and args.scan:
        parser.error('--synthetic is only for offline fixture reports')
    xml_path = args.xml
    try:
        if args.scan:
            if not args.authorized:
                parser.error('--scan requires --authorized')
            target = lab_target(args.scan)
            if not shutil.which('nmap'):
                parser.error('nmap is required for live scanning')
            args.out.mkdir(parents=True, exist_ok=True)
            xml_path = args.out / 'scan.xml'
            subprocess.run(['nmap', '-sT', '-sV', '--version-light', '-Pn', '-n',
                            '-p', '22,53,80,443,445,3389', '--host-timeout', '120s',
                            '-oX', str(xml_path), target], check=True, timeout=150)
        hosts = parse_scan(xml_path)
        evidence = 'SYNTHETIC TEST FIXTURE; NOT A LIVE SCAN' if args.synthetic else 'USER-SUPPLIED NMAP XML; VERIFY PROVENANCE'
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'inventory.json').write_text(json.dumps({'evidence': evidence, 'hosts': hosts}, indent=2) + '\n', encoding='utf-8')
        (args.out / 'report.md').write_text(markdown(hosts, evidence), encoding='utf-8')
        print(f'Reports written to {args.out}')
    except (OSError, ValueError, ET.ParseError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
