#!/usr/bin/env python3
"""
Educational Network Sniffer - Penetration Testing Tool
For authorized security testing and network analysis only.
Captures, parses, and analyzes network packets in real-time.
"""

import os
import sys
import time
import json
import struct
import socket
import threading
import logging
import getpass
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# =========================================================================
# ASCII LOGO BANNER
# =========================================================================

LOGO = r"""
███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗
██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

        ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
        ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
        ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
        ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
        ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
        ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
"""

# =========================================================================
# AUTHENTICATION
# =========================================================================

AUTHORIZED_USERS = {
    "admin": "elitejod"
}

def authenticate():
    """Prompt for username and password before allowing tool usage."""
    print(LOGO)
    print("=" * 60)
    print("  NETWORK SNIFFER - Authorized Access Required")
    print("=" * 60)
    print()

    for attempt in range(3):
        username = input("  Username: ").strip()
        password = getpass.getpass("  Password: ").strip()

        if username in AUTHORIZED_USERS and AUTHORIZED_USERS[username] == password:
            print(f"\n  [+] Access granted. Welcome, {username}.\n")
            return True
        else:
            remaining = 2 - attempt
            if remaining > 0:
                print(f"  [!] Invalid credentials. {remaining} attempt(s) remaining.\n")
            else:
                print("\n  [!] Too many failed attempts. Exiting.")
                sys.exit(1)


# Core packet manipulation library
try:
    from scapy.all import (
        sniff, wrpcap, rdpcap,
        IP, TCP, UDP, ICMP, ARP, DNS, DNSQR,
        Ether, Raw, conf
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy required: pip install scapy")
    print("[!] Falling back to raw socket mode (limited)")

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    # Fallback color stubs
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET = ""


# =========================================================================
# PACKET CAPTURE ENGINE
# =========================================================================

class NetworkSniffer:
    """
    Multi-mode network sniffer with protocol analysis.
    Supports Scapy (full) and raw socket (basic) backends.
    """

    def __init__(self, interface=None, output_dir="sniffer_output",
                 filter_expr=None, promiscuous=True):
        self.interface = interface or conf.iface if SCAPY_AVAILABLE else None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.filter_expr = filter_expr or ""
        self.promiscuous = promiscuous
        self.running = False

        # Statistics
        self.stats = {
            "total": 0,
            "tcp": 0, "udp": 0, "icmp": 0, "arp": 0,
            "dns": 0, "http": 0, "https": 0,
            "by_protocol": defaultdict(int),
            "top_talkers": defaultdict(int),
            "start_time": None
        }

        # Packet storage
        self.packets = []
        self.max_packets = 10000  # memory safeguard

        # Log files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pcap_file = self.output_dir / f"capture_{timestamp}.pcap"
        self.json_file = self.output_dir / f"capture_{timestamp}.json"
        self.text_file = self.output_dir / f"capture_{timestamp}.txt"

        logging.basicConfig(
            filename=self.output_dir / f"sniffer_{timestamp}.log",
            level=logging.INFO,
            format="%(asctime)s | %(message)s"
        )

    def _handle_packet_scapy(self, packet):
        """Scapy-based packet handler with full protocol parsing."""
        self.stats["total"] += 1
        self.stats["start_time"] = self.stats["start_time"] or time.time()

        entry = self._parse_packet_scapy(packet)
        if entry:
            self.packets.append(entry)

            # Live display
            self._display_packet(entry)

            # Check memory limit
            if len(self.packets) >= self.max_packets:
                self._flush_to_disk()
                self.packets = []

    def _parse_packet_scapy(self, packet):
        """Deep parse a Scapy packet into a structured dict."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "length": len(packet),
            "src_mac": None,
            "dst_mac": None,
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "protocol_number": None,
            "ttl": None,
            "payload": None,
            "details": {}
        }

        # Ethernet layer
        if Ether in packet:
            entry["src_mac"] = packet[Ether].src
            entry["dst_mac"] = packet[Ether].dst

        # IP layer
        if IP in packet:
            entry["src_ip"] = packet[IP].src
            entry["dst_ip"] = packet[IP].dst
            entry["ttl"] = packet[IP].ttl
            entry["protocol_number"] = packet[IP].proto
            self.stats["top_talkers"][packet[IP].src] += 1
            self.stats["top_talkers"][packet[IP].dst] += 1

        # TCP
        if TCP in packet:
            entry["protocol"] = "TCP"
            self.stats["tcp"] += 1
            entry["details"] = {
                "sport": packet[TCP].sport,
                "dport": packet[TCP].dport,
                "flags": self._tcp_flags(packet[TCP].flags),
                "seq": packet[TCP].seq,
                "ack": packet[TCP].ack,
                "window": packet[TCP].window
            }
            # Detect HTTPS
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                entry["protocol"] = "HTTPS"
                self.stats["https"] += 1

        # UDP
        elif UDP in packet:
            entry["protocol"] = "UDP"
            self.stats["udp"] += 1
            entry["details"] = {
                "sport": packet[UDP].sport,
                "dport": packet[UDP].dport,
                "length": packet[UDP].len
            }

        # ICMP
        elif ICMP in packet:
            entry["protocol"] = "ICMP"
            self.stats["icmp"] += 1
            entry["details"] = {
                "type": packet[ICMP].type,
                "code": packet[ICMP].code
            }

        # ARP
        elif ARP in packet:
            entry["protocol"] = "ARP"
            self.stats["arp"] += 1
            entry["details"] = {
                "op": 1 if packet[ARP].op == 1 else 2,  # who-has / is-at
                "psrc": packet[ARP].psrc,
                "pdst": packet[ARP].pdst,
                "hwsrc": packet[ARP].hwsrc,
                "hwdst": packet[ARP].hwdst
            }
            entry["src_ip"] = packet[ARP].psrc
            entry["dst_ip"] = packet[ARP].pdst

        # DNS
        if DNS in packet:
            self.stats["dns"] += 1
            dns_info = {"qr": "response" if packet[DNS].qr else "query", "id": packet[DNS].id}
            if DNSQR in packet:
                dns_info["query"] = packet[DNSQR].qname.decode(errors="ignore")
            if packet[DNS].an and packet[DNS].ancount > 0:
                answers = []
                for rr in packet[DNS].an:
                    if hasattr(rr, "rdata"):
                        answers.append(str(rr.rdata))
                dns_info["answers"] = answers
            entry["details"]["dns"] = dns_info

        # HTTP
        if HTTP in packet or (TCP in packet and packet[TCP].dport == 80):
            try:
                if Raw in packet:
                    raw = packet[Raw].load.decode(errors="ignore")
                    if raw.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "HTTP")):
                        self.stats["http"] += 1
                        entry["details"]["http"] = raw[:500]
                        entry["protocol"] = "HTTP"
            except Exception:
                pass

        # Raw payload
        if Raw in packet:
            raw_bytes = bytes(packet[Raw].load)
            # Only store printable/readable payloads
            try:
                payload_str = raw_bytes.decode("utf-8", errors="ignore")
                if any(c.isprintable() for c in payload_str[:100]):
                    entry["payload"] = payload_str[:500]
            except Exception:
                entry["payload"] = raw_bytes[:100].hex()

        self.stats["by_protocol"][entry["protocol"] or "OTHER"] += 1
        return entry

    def _tcp_flags(self, flags):
        """Decode TCP flag bits to human-readable string."""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return "/".join(flag_names) if flag_names else "."

    def _display_packet(self, entry):
        """Color-coded live output."""
        proto = entry["protocol"] or "OTHER"
        src = entry["src_ip"] or entry["src_mac"] or "???"
        dst = entry["dst_ip"] or entry["dst_mac"] or "???"

        # Color coding by protocol
        pcolor = Fore.WHITE
        if proto == "TCP": pcolor = Fore.GREEN
        elif proto == "UDP": pcolor = Fore.BLUE
        elif proto == "ICMP": pcolor = Fore.RED
        elif proto == "ARP": pcolor = Fore.YELLOW
        elif proto == "DNS": pcolor = Fore.MAGENTA
        elif proto == "HTTP": pcolor = Fore.CYAN
        elif proto == "HTTPS": pcolor = Fore.RED

        # Build display string
        line = f"{pcolor}[{proto:<6}] {Style.BRIGHT}{src:<15} -> {dst:<15}{Style.RESET_ALL}"

        if "sport" in entry.get("details", {}):
            line += f"  Port: {entry['details']['sport']}->{entry['details']['dport']}"

        if entry["details"].get("flags"):
            line += f"  Flags: {entry['details']['flags']}"

        if entry.get("payload") and len(entry["payload"]) > 3:
            payload_preview = entry["payload"][:80].replace("\n", " ")
            line += f"  Payload: {Fore.YELLOW}{payload_preview}"

        print(f"{Fore.WHITE}{entry['timestamp'][11:23]} |{line}")

    def _raw_socket_capture(self):
        """Fallback: raw socket capture without Scapy."""
        print("[!] Running in raw socket mode (limited protocol parsing)")
        
        # Create raw socket (requires root/admin)
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                sock.bind((self.interface, 0))
        except PermissionError:
            print("[!] Raw sockets require root/admin privileges")
            print("[!] Try: sudo python3 sniffer.py")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Socket error: {e}")
            sys.exit(1)

        print(f"[+] Listening on {self.interface or 'all interfaces'}...")
        self.running = True

        while self.running:
            try:
                raw_data, addr = sock.recvfrom(65535)
                self.stats["total"] += 1
                self.stats["start_time"] = self.stats["start_time"] or time.time()

                # Basic ethernet frame parsing
                eth_header = raw_data[:14]
                eth = struct.unpack("!6s6sH", eth_header)
                eth_type = socket.ntohs(eth[2])

                src_mac = ":".join(f"{b:02x}" for b in eth[0])
                dst_mac = ":".join(f"{b:02x}" for b in eth[1])

                proto_map = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
                proto_name = proto_map.get(eth_type, f"0x{eth_type:04x}")

                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "length": len(raw_data),
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "protocol": proto_name,
                    "src_ip": None,
                    "dst_ip": None,
                    "payload": raw_data[:100].hex(),
                    "details": {}
                }

                # Parse IP header if IPv4
                if eth_type == 0x0800 and len(raw_data) >= 34:
                    ip_header = raw_data[14:34]
                    ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    entry["protocol_number"] = ip_fields[6]
                    
                    src_ip = socket.inet_ntoa(ip_fields[8])
                    dst_ip = socket.inet_ntoa(ip_fields[9])
                    entry["src_ip"] = src_ip
                    entry["dst_ip"] = dst_ip
                    self.stats["top_talkers"][src_ip] += 1
                    self.stats["top_talkers"][dst_ip] += 1

                    # TCP
                    if ip_fields[6] == 6 and len(raw_data) > 54:
                        tcp_header = raw_data[34:54]
                        tcp_fields = struct.unpack("!HHIIBBHHH", tcp_header)
                        entry["protocol"] = "TCP"
                        entry["details"] = {
                            "sport": tcp_fields[0],
                            "dport": tcp_fields[1],
                            "flags": tcp_fields[5]
                        }
                    # UDP
                    elif ip_fields[6] == 17 and len(raw_data) > 42:
                        udp_header = raw_data[34:42]
                        udp_fields = struct.unpack("!HHHH", udp_header)
                        entry["protocol"] = "UDP"
                        entry["details"] = {
                            "sport": udp_fields[0],
                            "dport": udp_fields[1]
                        }

                self.packets.append(entry)
                self._display_packet(entry)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logging.error(f"Capture error: {e}")

    def start(self, count=0, timeout=None):
        """Start packet capture."""
        if SCAPY_AVAILABLE:
            print(f"[+] Starting Scapy-based sniffer")
            print(f"[+] Interface: {self.interface}")
            print(f"[+] Filter: {self.filter_expr or 'none'}")
            print(f"[+] Saving to: {self.pcap_file}")
            print(f"[+] Press Ctrl+C to stop\n")

            self.running = True
            try:
                sniff(
                    iface=self.interface,
                    prn=self._handle_packet_scapy,
                    filter=self.filter_expr or None,
                    store=False,
                    count=count or 0,
                    timeout=timeout,
                    promisc=self.promiscuous
                )
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()
        else:
            # Fallback raw socket (Linux only)
            self._raw_socket_capture()

    def stop(self):
        """Stop capture and save results."""
        self.running = False
        
        # Flush any remaining packets
        if self.packets:
            self._flush_to_disk()

        # Save PCAP if we used Scapy
        if SCAPY_AVAILABLE:
            print(f"\n[+] PCAP saved: {self.pcap_file}")

        # Print summary
        self._print_summary()
        logging.info("Capture session ended")

    def _flush_to_disk(self):
        """Write packets to disk (JSON + text log)."""
        if not self.packets:
            return

        # Append to JSON
        existing = []
        if self.json_file.exists():
            with open(self.json_file, "r") as f:
                try:
                    existing = json.load(f)
                except json.JSONDecodeError:
                    existing = []
        existing.extend(self.packets)
        with open(self.json_file, "w") as f:
            json.dump(existing, f, indent=2)

        # Append to text log
        with open(self.text_file, "a") as f:
            for p in self.packets:
                f.write(f"{p['timestamp']} | {p.get('protocol','?'):<6} "
                        f"{p.get('src_ip','?'):>15} -> {p.get('dst_ip','?'):<15}")
                if "sport" in p.get("details", {}):
                    f.write(f" Port:{p['details']['sport']}->{p['details']['dport']}")
                if p.get("payload"):
                    f.write(f" Payload:{p['payload'][:80]}")
                f.write("\n")

        self.packets = []

    def _print_summary(self):
        """Display capture statistics."""
        elapsed = time.time() - (self.stats["start_time"] or time.time())
        print("\n" + "=" * 60)
        print(f"  CAPTURE SUMMARY")
        print("=" * 60)
        print(f"  Duration:       {elapsed:.1f}s")
        print(f"  Total packets:  {self.stats['total']}")
        print(f"  TCP:            {self.stats['tcp']}")
        print(f"  UDP:            {self.stats['udp']}")
        print(f"  ICMP:           {self.stats['icmp']}")
        print(f"  ARP:            {self.stats['arp']}")
        print(f"  DNS:            {self.stats['dns']}")
        print(f"  HTTP:           {self.stats['http']}")
        print(f"  HTTPS:          {self.stats['https']}")
        print(f"\n  Protocol distribution:")
        for proto, count in sorted(self.stats['by_protocol'].items(), key=lambda x: -x[1]):
            pct = (count / max(self.stats['total'], 1)) * 100
            bar = "#" * int(pct // 5)
            print(f"    {proto:<10} {count:>6} ({pct:5.1f}%) {bar}")
        
        print(f"\n  Top talkers (source IPs):")
        for ip, count in sorted(self.stats['top_talkers'].items(), key=lambda x: -x[1])[:10]:
            print(f"    {ip:<20} {count:>6} packets")
        
        print(f"\n  Output files:")
        print(f"    JSON:  {self.json_file}")
        print(f"    Text:  {self.text_file}")
        print(f"    Log:   {self.output_dir / 'sniffer_*.log'}")
        print("=" * 60)


# =========================================================================
# ANALYSIS MODULE
# =========================================================================

class PacketAnalyzer:
    """Post-capture analysis tools."""

    @staticmethod
    def analyze_pcap(pcap_path):
        """Analyze an existing PCAP file."""
        if not SCAPY_AVAILABLE:
            print("[!] Scapy required for PCAP analysis")
            return

        print(f"[+] Analyzing {pcap_path}...\n")
        packets = rdpcap(pcap_path)

        stats = {
            "total": len(packets),
            "protocols": defaultdict(int),
            "ips": defaultdict(int),
            "ports": defaultdict(int),
            "dns_queries": [],
            "http_requests": []
        }

        for pkt in packets:
            if IP in pkt:
                stats["ips"][pkt[IP].src] += 1
                stats["ips"][pkt[IP].dst] += 1

            if TCP in pkt:
                proto = "TCP"
                stats["ports"][pkt[TCP].dport] += 1
            elif UDP in pkt:
                proto = "UDP"
                stats["ports"][pkt[UDP].dport] += 1
            elif ICMP in pkt:
                proto = "ICMP"
            elif ARP in pkt:
                proto = "ARP"
            else:
                proto = "OTHER"
            stats["protocols"][proto] += 1

            if DNS in pkt and DNSQR in pkt:
                stats["dns_queries"].append(
                    pkt[DNSQR].qname.decode(errors="ignore")
                )

            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                raw = pkt[Raw].load.decode(errors="ignore")
                if raw.startswith(("GET", "POST")):
                    stats["http_requests"].append(raw[:200])

        # Print analysis
        print("=" * 60)
        print("  PCAP ANALYSIS RESULTS")
        print("=" * 60)
        print(f"  Total packets: {stats['total']}")
        print(f"  Protocols:")
        for p, c in sorted(stats['protocols'].items(), key=lambda x: -x[1]):
            print(f"    {p}: {c}")
        print(f"\n  Top IPs:")
        for ip, c in sorted(stats['ips'].items(), key=lambda x: -x[1])[:10]:
            print(f"    {ip}: {c}")
        print(f"\n  Top destination ports:")
        for port, c in sorted(stats['ports'].items(), key=lambda x: -x[1])[:10]:
            service = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS",
                       25: "SMTP", 21: "FTP", 3389: "RDP"}.get(port, "?")
            print(f"    {port:<5} ({service:<6}): {c}")
        print(f"\n  DNS queries ({len(stats['dns_queries'])}):")
        for q in stats['dns_queries'][:15]:
            print(f"    {q}")
        print(f"\n  HTTP requests ({len(stats['http_requests'])}):")
        for r in stats['http_requests'][:10]:
            print(f"    {r[:100]}")
        print("=" * 60)


# =========================================================================
# MAIN INTERFACE
# =========================================================================

def print_logo():
    """Print the application logo banner."""
    if COLOR:
        print(f"{Fore.CYAN}{Style.BRIGHT}{LOGO}{Style.RESET_ALL}")
    else:
        print(LOGO)


def interactive_mode():
    """Menu-driven interface."""
    print("=" * 60)
    print("  NETWORK SNIFFER - Authorized Penetration Testing Tool")
    print("  For security research and network analysis")
    print("=" * 60)
    print()
    print("[1] Live capture (Scapy)")
    print("[2] Live capture (raw socket - basic)")
    print("[3] Analyze existing PCAP")
    print("[4] List available interfaces")
    print("[5] Exit")
    print()

    try:
        choice = input("Select option: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return

    if choice == "1":
        interface = input("Interface [auto]: ").strip() or None
        bpfilter = input("BPF filter [none]: ").strip() or ""
        sniffer = NetworkSniffer(
            interface=interface,
            filter_expr=bpfilter
        )
        sniffer.start()

    elif choice == "2":
        if SCAPY_AVAILABLE:
            print("[*] Scapy available — recommend option 1 for better results")
        interface = input("Interface [any]: ").strip() or None
        sniffer = NetworkSniffer(interface=interface)
        sniffer._raw_socket_capture()

    elif choice == "3":
        pcap = input("PCAP file path: ").strip()
        if Path(pcap).exists():
            PacketAnalyzer.analyze_pcap(pcap)
        else:
            print(f"[!] File not found: {pcap}")

    elif choice == "4":
        list_interfaces()

    elif choice == "5":
        print("[+] Exiting")


def list_interfaces():
    """Display available network interfaces."""
    if not SCAPY_AVAILABLE:
        print("[!] Scapy required to list interfaces")
        return
    
    print("\nAvailable interfaces:")
    print("-" * 40)
    for iface in conf.ifaces.values():
        ips = iface.ip if hasattr(iface, 'ip') else '?'
        print(f"  {iface.name:<10} IP: {ips:<15} MAC: {iface.mac}")
    print()


if __name__ == "__main__":
    # Authenticate first
    authenticate()

    # Check for admin/root
    if os.geteuid() != 0 and sys.platform != "win32":
        print("[!] Root/admin privileges recommended for packet capture")
        print("[!] Try: sudo python3 sniffer.py\n")

    # Quick start with CLI args
    if len(sys.argv) > 1:
        if sys.argv[1] == "--analyze" and len(sys.argv) > 2:
            print_logo()
            PacketAnalyzer.analyze_pcap(sys.argv[2])
        elif sys.argv[1] == "--interfaces":
            print_logo()
            list_interfaces()
        elif sys.argv[1] == "--capture":
            print_logo()
            iface = sys.argv[2] if len(sys.argv) > 2 else None
            sniffer = NetworkSniffer(interface=iface)
            sniffer.start()
        else:
            print_logo()
            print("Usage:")
            print("  python3 sniffer.py --capture [interface]")
            print("  python3 sniffer.py --analyze capture.pcap")
            print("  python3 sniffer.py --interfaces")
    else:
        interactive_mode()
