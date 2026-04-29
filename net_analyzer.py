#!/usr/bin/env python3
"""
NetSentinel - Offline Network Traffic Analyzer for Kali Linux
Analyzes PCAP files offline and generates structured PDF reports with risk scores.

Usage:
  python3 net_analyzer.py -f capture.pcap
  python3 net_analyzer.py -f capture.pcap -o report.pdf --json results.json
  python3 net_analyzer.py --demo          # generate a demo PCAP & analyze it
  python3 net_analyzer.py -f capture.pcap -v   # verbose

Install:
  pip3 install dpkt reportlab --break-system-packages
"""

import argparse, sys, os, json, socket, struct
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional

# ── Dependency guards ────────────────────────────────────────────────────────
try:
    import dpkt
    DPKT_OK = True
except ImportError:
    DPKT_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, PageBreak, HRFlowable)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    RL_OK = True
except ImportError:
    RL_OK = False

# ── Threat intelligence (offline) ───────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444:  ("Metasploit default listener", 9),
    1337:  ("Leet/common backdoor port",   8),
    31337: ("Back Orifice RAT",            9),
    6667:  ("IRC (botnet C2)",             7),
    6697:  ("IRC SSL (botnet C2)",         7),
    9001:  ("Tor relay",                   6),
    9050:  ("Tor SOCKS proxy",             7),
    9051:  ("Tor control port",            8),
    1080:  ("SOCKS proxy",                 5),
    23:    ("Telnet – cleartext",          7),
    21:    ("FTP – cleartext auth",        5),
    69:    ("TFTP – no auth",             6),
    5900:  ("VNC remote desktop",          6),
    6000:  ("X11 remote display",          7),
    12345: ("NetBus RAT",                  9),
    27374: ("SubSeven RAT",               9),
    65535: ("Common malware port",         8),
    2323:  ("Alt-Telnet backdoor",         7),
    8888:  ("Common alt shell port",       5),
}

CLEARTEXT_PROTOS = {21:"FTP",23:"Telnet",25:"SMTP",80:"HTTP",
                    110:"POP3",143:"IMAP",389:"LDAP",161:"SNMP",69:"TFTP"}

DNS_TUNNEL_THRESHOLD   = 50
PORT_SCAN_THRESHOLD    = 20
BEACON_STD_DEV_MAX     = 2.0   # seconds
BEACON_MIN_SAMPLES     = 15
DATA_EXFIL_THRESHOLD   = 10_000_000  # 10 MB
BRUTE_FORCE_THRESHOLD  = 20

RISK_LABELS = [
    (8.0, "CRITICAL", "#c0392b"),
    (6.0, "HIGH",     "#e67e22"),
    (3.0, "MEDIUM",   "#f39c12"),
    (0.0, "LOW",      "#27ae60"),
]

def risk_info(score: float):
    for lo, label, hex_col in RISK_LABELS:
        if score >= lo:
            return label, colors.HexColor(hex_col)
    return "LOW", colors.HexColor("#27ae60")

# ── PCAP parser (pure dpkt, no network interfaces needed) ───────────────────
class PcapParser:
    """Low-level packet reader using dpkt."""
    def __init__(self, path):
        self.path = path

    def iter_packets(self):
        with open(self.path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)
            for ts, raw in pcap:
                yield ts, raw

# ── Core analyzer ────────────────────────────────────────────────────────────
class TrafficAnalyzer:
    def __init__(self, pcap_path: str, verbose=False):
        self.path    = pcap_path
        self.verbose = verbose
        self.findings: List[dict] = []
        self.stats:    dict = {}

        self._host_bytes_out:     Dict[str, int]   = defaultdict(int)
        self._host_bytes_in:      Dict[str, int]   = defaultdict(int)
        self._host_dst_ports:     Dict[str, set]   = defaultdict(set)
        self._host_dns_queries:   Dict[str, list]  = defaultdict(list)
        self._host_connections:   Dict[str, set]   = defaultdict(set)
        self._conn_timestamps:    Dict[str, list]  = defaultdict(list)
        self._proto_counts:       Counter          = Counter()
        self._port_counts:        Counter          = Counter()
        self._arp_ip_to_macs:     Dict[str, set]   = defaultdict(set)
        self._seen_suspicious:    set              = set()
        self._seen_cleartext:     set              = set()

    # ── loading ──────────────────────────────────────────────────────────────
    def load_and_analyze(self) -> bool:
        if not DPKT_OK:
            print("[!] dpkt not installed. Run: pip3 install dpkt --break-system-packages"); return False
        if not os.path.exists(self.path):
            print(f"[!] File not found: {self.path}"); return False

        print(f"[*] Reading {self.path} …")
        parser = PcapParser(self.path)

        total, start_ts, end_ts = 0, None, None
        try:
            for ts, raw in parser.iter_packets():
                total += 1
                if start_ts is None: start_ts = ts
                end_ts = ts
                self._process_packet(ts, raw)
        except Exception as e:
            print(f"[!] Parse error: {e}"); return False

        if total == 0:
            print("[!] No packets found"); return False

        print(f"[+] Parsed {total:,} packets")
        self.stats["total_packets"] = total
        self.stats["capture_start"] = datetime.fromtimestamp(start_ts).isoformat() if start_ts else "N/A"
        self.stats["capture_end"]   = datetime.fromtimestamp(end_ts).isoformat()   if end_ts   else "N/A"
        self.stats["duration_sec"]  = round(end_ts - start_ts, 2) if (start_ts and end_ts) else 0
        self.stats["unique_hosts"]  = len(set(list(self._host_bytes_out) + list(self._host_bytes_in)))
        self.stats["protocol_dist"] = dict(self._proto_counts)

        self._run_detections()
        self.findings.sort(key=lambda x: -x["risk_score"])
        print(f"[+] {len(self.findings)} finding(s) detected")
        return True

    # ── per-packet processing ────────────────────────────────────────────────
    def _process_packet(self, ts: float, raw: bytes):
        try:
            eth = dpkt.ethernet.Ethernet(raw)
        except Exception:
            return

        # ARP
        if isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            if arp.op == dpkt.arp.ARP_OP_REPLY:
                try:
                    ip  = socket.inet_ntoa(arp.spa)
                    mac = ":".join(f"{b:02x}" for b in arp.sha)
                    self._arp_ip_to_macs[ip].add(mac)
                except Exception:
                    pass
            self._proto_counts["ARP"] += 1
            return

        if not isinstance(eth.data, dpkt.ip.IP):
            return

        ip  = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        plen = len(raw)
        self._host_bytes_out[src] += plen
        self._host_bytes_in[dst]  += plen
        self._host_connections[src].add(dst)

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            self._proto_counts["TCP"] += 1
            self._port_counts[tcp.dport] += 1
            self._host_dst_ports[src].add(tcp.dport)
            ckey = f"{src}->{dst}:{tcp.dport}"
            self._conn_timestamps[ckey].append(ts)

            # Suspicious ports
            for port, (reason, score) in SUSPICIOUS_PORTS.items():
                if tcp.dport == port or tcp.sport == port:
                    key = f"{src}:{port}"
                    if key not in self._seen_suspicious:
                        self._seen_suspicious.add(key)
                        self._add(
                            "Malicious Activity",
                            f"Suspicious Port {port} Traffic — {src} → {dst}",
                            f"Traffic on port {port} ({reason}) detected between {src} and {dst}.",
                            float(score),
                            [f"Src: {src}:{tcp.sport}", f"Dst: {dst}:{tcp.dport}",
                             f"Classification: {reason}"],
                            f"Investigate port {port} traffic immediately. Isolate hosts and perform "
                            f"forensic analysis. Block at firewall if not legitimate."
                        )

            # Cleartext protocols
            if tcp.dport in CLEARTEXT_PROTOS:
                key = f"{src}>{tcp.dport}"
                if key not in self._seen_cleartext:
                    self._seen_cleartext.add(key)
                    proto = CLEARTEXT_PROTOS[tcp.dport]

            # HTTP credential sniff
            if tcp.dport == 80 and tcp.data:
                try:
                    payload = tcp.data.decode(errors="ignore").lower()
                    if any(k in payload for k in ["password=","passwd=","pwd=","pass="]):
                        self._add(
                            "Credential Exposure",
                            f"Cleartext Password in HTTP POST — {src} → {dst}",
                            f"HTTP payload from {src} contains a password field sent in cleartext.",
                            8.5,
                            [f"Src: {src}", f"Dst: {dst}:80", "Keyword match: password/passwd/pwd"],
                            "Enforce HTTPS with HSTS. Audit all web forms for cleartext submission."
                        )
                except Exception:
                    pass

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            self._proto_counts["UDP"] += 1
            self._port_counts[udp.dport] += 1
            # DNS
            if udp.dport == 53 and udp.data:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_Q:
                        for q in dns.qd:
                            self._host_dns_queries[src].append(q.name)
                except Exception:
                    pass

        elif isinstance(ip.data, dpkt.icmp.ICMP):
            self._proto_counts["ICMP"] += 1

    # ── detection methods ─────────────────────────────────────────────────────
    def _add(self, cat, title, desc, score, evidence, rec):
        self.findings.append({
            "category": cat, "title": title,
            "description": desc, "risk_score": min(float(score), 10.0),
            "evidence": evidence[:8], "recommendation": rec,
        })
        if self.verbose:
            print(f"  [!] [{cat}] {title} (score={score:.1f})")

    def _run_detections(self):
        # Port scans
        for src, ports in self._host_dst_ports.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                score = min(5.0 + len(ports) / 20, 9.0)
                self._add("Reconnaissance",
                    f"Port Scan Detected — {src}",
                    f"{src} probed {len(ports)} distinct destination ports, consistent with automated scanning.",
                    score,
                    [f"Distinct ports probed: {len(ports)}",
                     f"Sample: {sorted(ports)[:15]}"],
                    "Block source IP at perimeter. Enable IPS port-scan signatures. Investigate host for compromise."
                )

        # Cleartext protocols (batch check)
        for key in self._seen_cleartext:
            src, port = key.split(">")
            port = int(port)
            proto = CLEARTEXT_PROTOS[port]
            self._add("Credential Exposure",
                f"Cleartext Protocol: {proto} from {src}",
                f"{proto} (port {port}) is unencrypted. Credentials transmitted are visible to anyone on the path.",
                6.5,
                [f"Protocol: {proto} (port {port})", f"Source: {src}"],
                f"Replace {proto} with its encrypted equivalent (SFTP/SSH/HTTPS/IMAPS/LDAPS). "
                f"Block plaintext variant at firewall."
            )

        # DNS tunneling
        for host, queries in self._host_dns_queries.items():
            if len(queries) > DNS_TUNNEL_THRESHOLD:
                long_q = [q for q in queries if len(q) > 50]
                ratio  = len(long_q) / max(len(queries), 1)
                score  = 8.5 if ratio > 0.5 else (7.0 if ratio > 0.2 else 5.0)
                self._add("Data Exfiltration",
                    f"DNS Tunneling Suspected — {host}",
                    f"{host} issued {len(queries)} DNS queries; {len(long_q)} had names >50 chars "
                    f"({ratio*100:.0f}%), indicating possible DNS tunneling.",
                    score,
                    [f"Total queries: {len(queries)}", f"Long-name queries: {len(long_q)}",
                     f"Ratio: {ratio*100:.1f}%"] + ([f"Sample: {long_q[0][:80]}"] if long_q else []),
                    "Deploy DNS monitoring/filtering. Block excessive or long-name queries. "
                    "Investigate host for dns2tcp, iodine, or dnscat tools."
                )

        # Data exfiltration
        for host, sent in self._host_bytes_out.items():
            if sent > DATA_EXFIL_THRESHOLD:
                mb = sent / 1_000_000
                self._add("Data Exfiltration",
                    f"High Outbound Volume — {host}",
                    f"{host} sent {mb:.1f} MB outbound, exceeding the {DATA_EXFIL_THRESHOLD/1e6:.0f} MB threshold.",
                    min(5.0 + mb / 100, 9.5),
                    [f"Bytes sent: {sent:,} ({mb:.1f} MB)",
                     f"Unique destinations: {len(self._host_connections[host])}"],
                    "Implement DLP controls. Review outbound firewall rules. Correlate with user activity logs."
                )

        # C2 beaconing
        for conn_key, timestamps in self._conn_timestamps.items():
            if len(timestamps) < BEACON_MIN_SAMPLES:
                continue
            timestamps.sort()
            intervals = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
            avg = sum(intervals) / len(intervals)
            if avg < 0.01:
                continue
            variance = sum((x-avg)**2 for x in intervals) / len(intervals)
            std_dev  = variance ** 0.5
            if std_dev < BEACON_STD_DEV_MAX:
                self._add("C2 Communication",
                    f"Beaconing Detected — {conn_key}",
                    f"Regular {avg:.1f}s ± {std_dev:.2f}s intervals over {len(timestamps)} packets — "
                    f"consistent with automated C2 heartbeat.",
                    7.5,
                    [f"Connection: {conn_key}", f"Packets: {len(timestamps)}",
                     f"Avg interval: {avg:.2f}s", f"Std deviation: {std_dev:.4f}s"],
                    "Isolate beaconing host immediately. Perform memory forensics. "
                    "Block C2 destination at firewall/proxy."
                )

        # ARP spoofing
        for ip, macs in self._arp_ip_to_macs.items():
            if len(macs) > 1:
                self._add("Network Attack",
                    f"ARP Spoofing / Cache Poisoning — {ip}",
                    f"IP {ip} appeared with {len(macs)} different MAC addresses in ARP replies.",
                    9.0,
                    [f"IP: {ip}", f"MACs observed: {list(macs)}"],
                    "Enable Dynamic ARP Inspection (DAI). Add static ARP entries for critical hosts. "
                    "Investigate for active MITM attack."
                )

        # Brute force
        auth_ports = {22:"SSH",21:"FTP",3389:"RDP",23:"Telnet",
                      5900:"VNC",25:"SMTP",110:"POP3",143:"IMAP"}
        seen_bf: Dict[str, int] = defaultdict(int)
        for ckey, ts_list in self._conn_timestamps.items():
            try:
                dst_port = int(ckey.split(":")[-1])
            except Exception:
                continue
            if dst_port in auth_ports:
                seen_bf[ckey] += len(ts_list)
        for ckey, count in seen_bf.items():
            if count >= BRUTE_FORCE_THRESHOLD:
                try: dst_port = int(ckey.split(":")[-1])
                except: dst_port = 0
                proto = auth_ports.get(dst_port, "Unknown")
                src   = ckey.split("->")[0]
                self._add("Brute Force",
                    f"{proto} Brute Force — {ckey}",
                    f"{count} connection attempts to {proto} (port {dst_port}) from {src}.",
                    min(5.0 + count/30, 9.0),
                    [f"Source: {src}", f"Service: {proto} (port {dst_port})",
                     f"Attempts: {count}"],
                    f"Block source IP. Enable account lockout on {proto}. "
                    f"Deploy fail2ban. Use key-based authentication where possible."
                )

    # ── helpers ───────────────────────────────────────────────────────────────
    def overall_risk_score(self) -> float:
        if not self.findings: return 0.0
        top3 = sorted([f["risk_score"] for f in self.findings], reverse=True)[:3]
        return round(sum(top3) / len(top3), 2)

    def category_summary(self) -> Dict[str, int]:
        c: Counter = Counter()
        for f in self.findings: c[f["category"]] += 1
        return dict(c)


# ── PDF report generator ─────────────────────────────────────────────────────
class ReportGenerator:
    PW, PH = A4
    M = 2 * cm

    C_BG    = colors.HexColor("#0d1117")
    C_PANEL = colors.HexColor("#161b22")
    C_ACCENT= colors.HexColor("#58a6ff")
    C_BORDER= colors.HexColor("#30363d")
    C_TEXT  = colors.HexColor("#e6edf3")
    C_SUB   = colors.HexColor("#8b949e")

    def __init__(self, a: TrafficAnalyzer, out: str):
        self.a   = a
        self.out = out
        self._mk_styles()

    def _mk_styles(self):
        def ps(n, **kw): return ParagraphStyle(n, **kw)
        self.s_title  = ps("t",  fontSize=24, fontName="Helvetica-Bold",
                           textColor=colors.white, alignment=TA_CENTER, spaceAfter=4)
        self.s_sub    = ps("sb", fontSize=11, fontName="Helvetica",
                           textColor=self.C_SUB, alignment=TA_CENTER, spaceAfter=16)
        self.s_h1     = ps("h1", fontSize=14, fontName="Helvetica-Bold",
                           textColor=self.C_ACCENT, spaceBefore=12, spaceAfter=6)
        self.s_h2     = ps("h2", fontSize=11, fontName="Helvetica-Bold",
                           textColor=colors.white, spaceBefore=8, spaceAfter=4)
        self.s_body   = ps("bo", fontSize=9,  fontName="Helvetica",
                           textColor=self.C_TEXT, spaceAfter=4, leading=13)
        self.s_small  = ps("sm", fontSize=8,  fontName="Helvetica",
                           textColor=self.C_SUB, spaceAfter=2)
        self.s_green  = ps("gr", fontSize=9,  fontName="Helvetica-Oblique",
                           textColor=colors.HexColor("#56d364"), spaceBefore=3, spaceAfter=3)

    def _page_bg(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(self.C_BG)
        canvas.rect(0, 0, self.PW, self.PH, fill=1, stroke=0)
        canvas.setFillColor(self.C_ACCENT)
        canvas.rect(0, self.PH-5, self.PW, 5, fill=1, stroke=0)
        canvas.setFillColor(self.C_BORDER)
        canvas.rect(0, 0, self.PW, 18, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(self.C_SUB)
        canvas.drawString(self.M, 5, "NetSentinel — Confidential — For Authorized Use Only")
        canvas.drawRightString(self.PW - self.M, 5, f"Page {doc.page}")
        canvas.restoreState()

    def _tbl(self, col=None):
        hc = col or self.C_ACCENT
        return TableStyle([
            ("BACKGROUND",    (0,0), (-1, 0), hc),
            ("TEXTCOLOR",     (0,0), (-1, 0), self.C_BG),
            ("FONTNAME",      (0,0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1, 0), 8),
            ("BACKGROUND",    (0,1), (-1,-1), self.C_PANEL),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [self.C_PANEL, colors.HexColor("#1c2128")]),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,1), (-1,-1), 8),
            ("TEXTCOLOR",     (0,1), (-1,-1), self.C_TEXT),
            ("GRID",          (0,0), (-1,-1), 0.3, self.C_BORDER),
            ("ALIGN",         (0,0), (-1,-1), "LEFT"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("RIGHTPADDING",  (0,0), (-1,-1), 6),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ])

    # sections ----------------------------------------------------------------
    def _cover(self):
        s = [Spacer(1, 1.6*cm),
             Paragraph("NetSentinel", self.s_title),
             Paragraph("Network Traffic Security Analysis Report", self.s_sub),
             HRFlowable(width="100%", thickness=1, color=self.C_ACCENT),
             Spacer(1, 0.5*cm)]
        meta = [
            ["Capture File",   os.path.basename(self.a.path)],
            ["Report Time",    datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Capture Start",  self.a.stats.get("capture_start","N/A")],
            ["Capture End",    self.a.stats.get("capture_end","N/A")],
            ["Duration",       f"{self.a.stats.get('duration_sec',0)} s"],
            ["Total Packets",  f"{self.a.stats.get('total_packets',0):,}"],
            ["Unique Hosts",   str(self.a.stats.get("unique_hosts",0))],
            ["Total Findings", str(len(self.a.findings))],
        ]
        t = Table(meta, colWidths=[5*cm, 11*cm])
        t.setStyle(self._tbl())
        s.append(t)
        s.append(Spacer(1, 0.7*cm))
        score = self.a.overall_risk_score()
        label, col = risk_info(score)
        rt = Table([[" OVERALL RISK SCORE ", f" {score:.1f} / 10 ", f" {label} "]],
                   colWidths=[6*cm, 5*cm, 5*cm])
        rt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), col),
            ("TEXTCOLOR",     (0,0), (-1,-1), self.C_BG),
            ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (0,-1),  9),
            ("FONTSIZE",      (1,0), (1,-1),  20),
            ("FONTSIZE",      (2,0), (2,-1),  13),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ]))
        s.append(rt)
        return s

    def _exec_summary(self):
        s  = [Paragraph("1. Executive Summary", self.s_h1)]
        score = self.a.overall_risk_score()
        label, _ = risk_info(score)
        cats = self.a.category_summary()
        txt = (f"Traffic capture <b>{os.path.basename(self.a.path)}</b> spans "
               f"{self.a.stats.get('duration_sec',0)}s and contains "
               f"{self.a.stats.get('total_packets',0):,} packets across "
               f"{self.a.stats.get('unique_hosts',0)} unique hosts. "
               f"Analysis identified <b>{len(self.a.findings)} finding(s)</b> "
               f"with overall risk <b>{score}/10 ({label})</b>.")
        s.append(Paragraph(txt, self.s_body))
        s.append(Spacer(1, 0.3*cm))
        if cats:
            CAT_WEIGHT = {"Malicious Activity":"CRITICAL","Network Attack":"CRITICAL",
                          "C2 Communication":"HIGH","Brute Force":"HIGH",
                          "Data Exfiltration":"HIGH","Credential Exposure":"MEDIUM",
                          "Reconnaissance":"MEDIUM"}
            rows = [["Category","Count","Severity"]]
            for cat, cnt in sorted(cats.items(), key=lambda x:-x[1]):
                rows.append([cat, str(cnt), CAT_WEIGHT.get(cat,"LOW")])
            t = Table(rows, colWidths=[8*cm, 3*cm, 5*cm])
            t.setStyle(self._tbl())
            s.append(t)
        return s

    def _stats(self):
        s = [Paragraph("2. Traffic Statistics", self.s_h1)]
        proto = self.a.stats.get("protocol_dist", {})
        if proto:
            s.append(Paragraph("Protocol Distribution", self.s_h2))
            total = sum(proto.values()) or 1
            rows  = [["Protocol","Packets","Share"]]
            for p, c in sorted(proto.items(), key=lambda x:-x[1]):
                rows.append([p, f"{c:,}", f"{c/total*100:.1f}%"])
            t = Table(rows, colWidths=[5*cm, 5*cm, 6*cm])
            t.setStyle(self._tbl())
            s.append(t)
            s.append(Spacer(1, 0.3*cm))

        s.append(Paragraph("Top Talkers (Outbound)", self.s_h2))
        top10 = sorted(self.a._host_bytes_out.items(), key=lambda x:-x[1])[:10]
        if top10:
            rows = [["Host IP","Bytes Sent","MB","Destinations"]]
            for ip, b in top10:
                rows.append([ip, f"{b:,}", f"{b/1e6:.2f}", str(len(self.a._host_connections[ip]))])
            t = Table(rows, colWidths=[4.5*cm, 4*cm, 3*cm, 4.5*cm])
            t.setStyle(self._tbl())
            s.append(t)

        s.append(Spacer(1, 0.3*cm))
        s.append(Paragraph("Top Destination Ports", self.s_h2))
        top_ports = self.a._port_counts.most_common(12)
        if top_ports:
            SVC = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",25:"SMTP",53:"DNS",
                   3306:"MySQL",3389:"RDP",8080:"HTTP-Alt",445:"SMB",
                   23:"Telnet",110:"POP3",143:"IMAP",993:"IMAPS"}
            rows = [["Port","Service","Packets"]]
            for port, cnt in top_ports:
                rows.append([str(port), SVC.get(port,"Unknown"), f"{cnt:,}"])
            t = Table(rows, colWidths=[3*cm, 5*cm, 8*cm])
            t.setStyle(self._tbl())
            s.append(t)
        return s

    def _findings(self):
        s = [Paragraph("3. Security Findings", self.s_h1)]
        if not self.a.findings:
            s.append(Paragraph("No security findings detected.", self.s_body))
            return s
        s.append(Paragraph(f"{len(self.a.findings)} finding(s) listed by descending risk score.", self.s_body))

        for i, f in enumerate(self.a.findings, 1):
            score = f["risk_score"]
            label, col = risk_info(score)

            hdr = Table([[f"  #{i}  {f['title']}", f"{label}  {score:.1f}/10"]],
                        colWidths=[13*cm, 3*cm])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), col),
                ("TEXTCOLOR",     (0,0), (-1,-1), self.C_BG),
                ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,-1), 9),
                ("ALIGN",         (1,0), (1,-1),  "RIGHT"),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 6),
                ("RIGHTPADDING",  (0,0), (-1,-1), 6),
            ]))
            s.append(hdr)

            ev = "\n".join(f"• {e}" for e in f.get("evidence",[]))
            body = Table([
                ["Category:",       f["category"]],
                ["Description:",    f["description"]],
                ["Evidence:",       ev],
                ["Recommendation:", f["recommendation"]],
            ], colWidths=[3.5*cm, 12.5*cm])
            body.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), self.C_PANEL),
                ("TEXTCOLOR",     (0,0), (0,-1),  self.C_SUB),
                ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
                ("TEXTCOLOR",     (1,0), (-1,-1), self.C_TEXT),
                ("FONTNAME",      (1,0), (-1,-1), "Helvetica"),
                ("FONTSIZE",      (0,0), (-1,-1), 8),
                ("GRID",          (0,0), (-1,-1), 0.3, self.C_BORDER),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ("LEFTPADDING",   (0,0), (-1,-1), 6),
                ("RIGHTPADDING",  (0,0), (-1,-1), 6),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("TEXTCOLOR",     (1,3), (1,3),   colors.HexColor("#56d364")),
                ("FONTNAME",      (1,3), (1,3),   "Helvetica-Oblique"),
            ]))
            s.append(body)
            s.append(Spacer(1, 0.3*cm))
        return s

    def _risk_matrix(self):
        s = [Paragraph("4. Risk Score Matrix", self.s_h1),
             Paragraph("Scores are 0–10, derived from detection heuristics, volume analysis, "
                       "behavioural patterns, and known-malicious port intelligence.", self.s_body),
             Spacer(1, 0.2*cm)]
        rows = [
            ["Range", "Level",    "Colour",  "Required Action"],
            ["0–2.9", "LOW",      "Green",   "Monitor passively. No immediate action."],
            ["3–5.9", "MEDIUM",   "Yellow",  "Investigate within 72 hours."],
            ["6–7.9", "HIGH",     "Orange",  "Investigate within 24 hours. Escalate to security team."],
            ["8–10",  "CRITICAL", "Red",     "Immediate response. Isolate hosts. Engage IR team."],
        ]
        t = Table(rows, colWidths=[3*cm, 3*cm, 3*cm, 7*cm])
        ts = self._tbl()
        for i, (lo, lbl, c) in enumerate(
                [(3,"LOW","#1a3a2a"),(4,"MED","#3a3010"),(5,"HIGH","#3a2010"),(6,"CRIT","#3a1010")]):
            ts.add("BACKGROUND", (0,i), (-1,i), colors.HexColor(c))
        t.setStyle(ts)
        s.append(t)
        return s

    def _recommendations(self):
        s = [Paragraph("5. Consolidated Recommendations", self.s_h1)]
        seen, recs = set(), []
        for f in self.a.findings:
            r = f["recommendation"]
            if r not in seen:
                seen.add(r)
                recs.append((f["category"], f["risk_score"], r))
        recs.sort(key=lambda x: -x[1])
        if not recs:
            s.append(Paragraph("No specific recommendations at this time.", self.s_body))
            return s
        rows = [["#", "Category", "Risk", "Recommendation"]]
        for idx, (cat, sc, rec) in enumerate(recs, 1):
            lbl, _ = risk_info(sc)
            rows.append([str(idx), cat, f"{sc:.1f}/{lbl}", rec])
        t = Table(rows, colWidths=[0.7*cm, 4*cm, 2.3*cm, 9*cm])
        t.setStyle(self._tbl())
        s.append(t)
        return s

    def _appendix(self):
        s = [Paragraph("Appendix A — Detection Methodology", self.s_h1)]
        methods = [
            ("Port Scan",          f"Source probed >= {PORT_SCAN_THRESHOLD} distinct destination ports."),
            ("Suspicious Ports",   "Traffic matched built-in database of known malicious ports."),
            ("Cleartext Protocol", "Unencrypted protocols detected (FTP/Telnet/HTTP/SMTP/POP3/IMAP/LDAP/SNMP/TFTP)."),
            ("DNS Tunneling",      f"Host issued >{DNS_TUNNEL_THRESHOLD} DNS queries; high proportion of long-name entries."),
            ("Data Exfiltration",  f"Host sent >{DATA_EXFIL_THRESHOLD/1e6:.0f} MB outbound."),
            ("C2 Beaconing",       f"Connection with regular intervals (std dev <{BEACON_STD_DEV_MAX}s) over >= {BEACON_MIN_SAMPLES} packets."),
            ("ARP Spoofing",       "Same IP seen with multiple MAC addresses in ARP replies."),
            ("Brute Force",        f">= {BRUTE_FORCE_THRESHOLD} connection attempts to auth service from single source."),
            ("HTTP Credential",    "HTTP POST payload contains password/passwd/pwd keyword."),
        ]
        rows = [["Detection", "Method"]] + list(methods)
        t = Table(rows, colWidths=[5*cm, 11*cm])
        t.setStyle(self._tbl())
        s.append(t)
        return s

    def generate(self) -> bool:
        if not RL_OK:
            print("[!] ReportLab missing. Run: pip3 install reportlab --break-system-packages")
            return False
        print(f"[*] Writing PDF → {self.out}")
        doc = SimpleDocTemplate(self.out, pagesize=A4,
                                leftMargin=self.M, rightMargin=self.M,
                                topMargin=self.M+0.3*cm, bottomMargin=self.M)
        story = []
        story += self._cover();         story.append(PageBreak())
        story += self._exec_summary();  story.append(Spacer(1, 0.3*cm))
        story += self._stats();         story.append(PageBreak())
        story += self._findings();      story.append(PageBreak())
        story += self._risk_matrix();   story.append(Spacer(1, 0.3*cm))
        story += self._recommendations(); story.append(PageBreak())
        story += self._appendix()
        doc.build(story, onFirstPage=self._page_bg, onLaterPages=self._page_bg)
        print(f"[+] PDF saved: {self.out}")
        return True


# ── Demo PCAP generator ───────────────────────────────────────────────────────
def build_demo_pcap(path: str) -> bool:
    """Write a synthetic PCAP with intentional anomalies for testing."""
    import struct, time

    def ipstr(ip): return socket.inet_aton(ip)

    def eth_ip_tcp(src_ip, dst_ip, sport, dport, payload=b""):
        eth = b"\xff\xff\xff\xff\xff\xff" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00"
        # IP header (minimal)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
                             0x45, 0, 40+len(payload), 0x1234, 0, 64, 6, 0,
                             ipstr(src_ip), ipstr(dst_ip))
        # TCP header
        tcp_hdr = struct.pack("!HHLLBBHHH",
                              sport, dport, 0, 0, 0x50, 0x18, 65535, 0, 0)
        return eth + ip_hdr + tcp_hdr + payload

    def eth_ip_udp_dns(src_ip, dst_ip, qname):
        label = b""
        for part in qname.rstrip(".").split("."):
            enc = part.encode()
            label += bytes([len(enc)]) + enc
        label += b"\x00"
        dns_payload = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                       + label + b"\x00\x01\x00\x01")
        eth = b"\xff\xff\xff\xff\xff\xff" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00"
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
                             0x45, 0, 28+len(dns_payload), 0x1235, 0, 64, 17, 0,
                             ipstr(src_ip), ipstr(dst_ip))
        udp_hdr = struct.pack("!HHHH", 54321, 53, 8+len(dns_payload), 0)
        return eth + ip_hdr + udp_hdr + dns_payload

    def eth_arp_reply(sender_ip, sender_mac_bytes, target_ip):
        eth = b"\xff"*6 + sender_mac_bytes + b"\x08\x06"
        arp = struct.pack("!HHBBH",1,0x0800,6,4,2) + sender_mac_bytes + ipstr(sender_ip) + b"\x00"*6 + ipstr(target_ip)
        return eth + arp

    # Write pcap header + records
    PCAP_MAGIC = 0xa1b2c3d4
    pcap_hdr   = struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)
    base_ts    = int(time.time()) - 3600
    records    = []

    def rec(ts_offset, pkt):
        ts_sec  = int(base_ts + ts_offset)
        ts_usec = 0
        records.append(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)

    # Normal HTTPS
    for i in range(40):
        rec(i*0.1, eth_ip_tcp("192.168.1.10","93.184.216.34", 50000+i, 443))

    # Port scan
    for port in range(1, 130):
        rec(20 + port*0.02, eth_ip_tcp("192.168.1.20","192.168.1.1", 54321, port))

    # Metasploit port 4444
    for i in range(6):
        rec(40+i, eth_ip_tcp("10.0.0.5","192.168.1.50", 4444, 4444, b"SHELLCODE"*8))

    # Telnet
    rec(50, eth_ip_tcp("192.168.1.30","192.168.1.1", 55000, 23, b"user admin\npassword s3cr3t\n"))

    # FTP
    rec(51, eth_ip_tcp("192.168.1.30","192.168.1.2", 55001, 21, b"USER admin\nPASS hunter2\n"))

    # DNS tunneling
    for i in range(85):
        long_q = f"aaabbb{i:04d}{'x'*30}.tunnel.evil.com"
        rec(60 + i*0.3, eth_ip_udp_dns("192.168.1.40","8.8.8.8", long_q))

    # Beaconing (60s intervals)
    for i in range(20):
        rec(200 + i*60, eth_ip_tcp("192.168.1.60","185.220.101.1", 33333, 8080, b"GET / HTTP/1.1\r\n"))

    # ARP spoofing (two MACs claim same IP)
    rec(500, eth_arp_reply("192.168.1.1", b"\xaa\xbb\xcc\xdd\xee\x01","192.168.1.100"))
    rec(501, eth_arp_reply("192.168.1.1", b"\xff\xee\xdd\xcc\xbb\x02","192.168.1.100"))

    # SSH brute force
    for i in range(45):
        rec(600 + i*0.5, eth_ip_tcp("10.0.0.99","192.168.1.10", 60000+i, 22))

    # Large outbound (data exfil)
    for i in range(3000):
        rec(800 + i*0.005, eth_ip_tcp("192.168.1.70","45.33.32.156", 44444, 80, b"D"*4000))

    # HTTP with password in POST
    rec(2000, eth_ip_tcp("192.168.1.80","10.0.0.1", 50099, 80,
                         b"POST /login HTTP/1.1\r\nHost: internal\r\n\r\nusername=admin&password=admin123"))

    with open(path, "wb") as f:
        f.write(pcap_hdr)
        for r in records:
            f.write(r)
    print(f"[+] Demo PCAP written: {path} ({len(records)} packets)")
    return True


# ── JSON export ───────────────────────────────────────────────────────────────
def export_json(a: TrafficAnalyzer, path: str):
    out = {
        "report_generated": datetime.now().isoformat(),
        "pcap_file": a.path,
        "overall_risk_score": a.overall_risk_score(),
        "risk_label": risk_info(a.overall_risk_score())[0],
        "stats": a.stats,
        "category_summary": a.category_summary(),
        "findings": [{k:v for k,v in f.items() if not k.startswith("_")} for f in a.findings],
    }
    with open(path,"w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[+] JSON saved: {path}")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel — Offline Network Traffic Analyzer for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 net_analyzer.py -f capture.pcap
  python3 net_analyzer.py -f capture.pcap -o my_report.pdf --json findings.json
  python3 net_analyzer.py --demo
  python3 net_analyzer.py -f capture.pcap -v

Install:
  pip3 install dpkt reportlab --break-system-packages
        """)
    parser.add_argument("-f","--file",   help="Path to PCAP/PCAPNG file")
    parser.add_argument("-o","--output", default="netsentinel_report.pdf",
                        help="Output PDF path (default: netsentinel_report.pdf)")
    parser.add_argument("--json",        help="Also export findings as JSON")
    parser.add_argument("-v","--verbose",action="store_true", help="Verbose output")
    parser.add_argument("--demo",        action="store_true",
                        help="Build a demo PCAP with synthetic anomalies and analyze it")
    args = parser.parse_args()

    print("""
 ███╗  ██╗███████╗████████╗███████╗███████╗███╗  ██╗████████╗██╗███╗  ██╗███████╗██╗
 ████╗ ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║
 ██╔██╗██║█████╗     ██║   ███████╗█████╗  ██╔██╗██║   ██║   ██║██╔██╗██║█████╗  ██║
 ██║╚████║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚████║   ██║   ██║██║╚████║██╔══╝  ██║
 ██║ ╚███║███████╗   ██║   ███████║███████╗██║ ╚███║   ██║   ██║██║ ╚███║███████╗███████╗
 ╚═╝  ╚══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝
    Offline Network Traffic Analyzer  |  Kali Linux Edition
    """)

    if not DPKT_OK:
        print("[!] dpkt not installed: pip3 install dpkt --break-system-packages"); sys.exit(1)
    if not RL_OK:
        print("[!] reportlab not installed: pip3 install reportlab --break-system-packages"); sys.exit(1)

    pcap_path = args.file
    if args.demo:
        pcap_path = "/tmp/netsentinel_demo.pcap"
        build_demo_pcap(pcap_path)
    elif not pcap_path:
        parser.print_help(); sys.exit(0)

    a = TrafficAnalyzer(pcap_path, verbose=args.verbose)
    if not a.load_and_analyze():
        sys.exit(1)

    score = a.overall_risk_score()
    label, _ = risk_info(score)
    print(f"\n{'─'*55}")
    print(f"  Overall Risk Score : {score:.1f}/10  [{label}]")
    print(f"  Total Findings     : {len(a.findings)}")
    for cat, cnt in a.category_summary().items():
        print(f"    • {cat:<28} {cnt}")
    print(f"{'─'*55}\n")

    rg = ReportGenerator(a, args.output)
    rg.generate()
    if args.json:
        export_json(a, args.json)
    print("[✓] Done.\n")

if __name__ == "__main__":
    main()
