"""Vulnerability intelligence for network ports.

Policy: **only TCP/443 (HTTPS) is permitted to be open.** Every other port
that is reachable (open or filtered) is reported as a policy violation
with detailed vulnerability context.

Each entry returns service identity, vulnerability class, technical
description, attack vector, mitigation guidance, and framework references
(CVE, CWE, CIS, OWASP, MITRE ATT&CK). This is intentionally conservative
so the scanner output is dashboard- and audit-ready.
"""

from typing import Dict, List, Optional


PORT_INTEL: Dict[int, Dict[str, object]] = {
    21: {
        'service': 'ftp',
        'class': 'cleartext credentials & data exfiltration',
        'description': 'File Transfer Protocol transmits usernames, passwords, and payload data in cleartext.',
        'attack_vector': 'Passive sniffing of the network captures credentials; anonymous-FTP misconfiguration leaks files; banner-grabbing fingerprints daemon for known CVEs.',
        'mitigation': 'Disable or replace with SFTP (port 22 inside a bastion) or FTPS over TLS 1.2+; block 21/tcp at the perimeter.',
        'references': ['CWE-319', 'CVE-2010-4221', 'CIS Controls 4.5', 'MITRE ATT&CK T1021'],
        'severity': 'critical',
    },
    22: {
        'service': 'ssh',
        'class': 'remote interactive shell',
        'description': 'Secure Shell allows interactive remote administration. Exposure to the internet enables credential brute-force and lateral movement after compromise.',
        'attack_vector': 'Username enumeration, credential spraying, weak key reuse, agent-forwarding abuse, supply-chain key theft.',
        'mitigation': 'Restrict to bastion hosts behind a VPN; enforce key-based auth + hardware MFA; deny root login; fail2ban; audit authorized_keys.',
        'references': ['CWE-307', 'CIS Benchmark §5.2', 'MITRE ATT&CK T1021.004', 'NIST 800-53 AC-17'],
        'severity': 'critical',
    },
    23: {
        'service': 'telnet',
        'class': 'cleartext remote shell',
        'description': 'Telnet provides interactive shell access with no encryption; all session traffic including passwords is sniffable.',
        'attack_vector': 'Network sniffing, MITM, banner-grabbing for embedded-device exploitation.',
        'mitigation': 'Decommission entirely; replace with SSH; block 23/tcp at every boundary.',
        'references': ['CWE-319', 'CWE-326', 'CIS Controls 4.5'],
        'severity': 'critical',
    },
    25: {
        'service': 'smtp',
        'class': 'mail relay abuse',
        'description': 'Simple Mail Transfer Protocol open to the internet is a common open-relay and spoofing target.',
        'attack_vector': 'Open-relay abuse, sender-spoofing, VRFY/EXPN user enumeration, STARTTLS downgrade.',
        'mitigation': 'Require authentication and TLS; block 25/tcp inbound to non-MTA hosts; configure SPF/DKIM/DMARC.',
        'references': ['CWE-693', 'RFC 7208', 'CIS Email §6'],
        'severity': 'high',
    },
    53: {
        'service': 'dns',
        'class': 'DNS amplification & zone transfer',
        'description': 'DNS over an open resolver enables reflection/amplification DDoS and zone-walking for reconnaissance.',
        'attack_vector': 'Recursive abuse for DDoS amplification; AXFR zone transfer leaking the internal namespace; DNS rebinding.',
        'mitigation': 'Disable recursion for external clients; restrict AXFR to trusted secondaries; enable DNSSEC; firewall 53/tcp inbound.',
        'references': ['CWE-406', 'US-CERT TA13-088A'],
        'severity': 'high',
    },
    69: {
        'service': 'tftp',
        'class': 'firmware/file theft',
        'description': 'Trivial FTP provides unauthenticated file transfer over UDP — typically used by network gear for configs and firmware.',
        'attack_vector': 'Anonymous read of configs containing secrets; arbitrary write of malicious firmware.',
        'mitigation': 'Disable on production hosts; restrict to isolated provisioning networks; rotate any leaked credentials.',
        'references': ['CWE-306', 'CIS Controls 12.4'],
        'severity': 'critical',
    },
    80: {
        'service': 'http',
        'class': 'unencrypted web traffic',
        'description': 'Plain HTTP exposes session cookies, credentials, and PII to passive observers and MITM.',
        'attack_vector': 'Network sniffing, SSL stripping, cookie hijacking, content injection.',
        'mitigation': 'Redirect 301 → HTTPS; enable HSTS with preload; remove the HTTP listener entirely once HSTS is established.',
        'references': ['CWE-319', 'OWASP A02:2021', 'NIST SP 800-52'],
        'severity': 'high',
    },
    110: {
        'service': 'pop3',
        'class': 'cleartext mail retrieval',
        'description': 'POP3 transmits mailbox credentials and messages without encryption.',
        'attack_vector': 'Credential capture by sniffing; brute-force of mailbox passwords.',
        'mitigation': 'Disable; use POP3S (995) or IMAPS with TLS only; require strong authentication.',
        'references': ['CWE-319'],
        'severity': 'high',
    },
    135: {
        'service': 'msrpc',
        'class': 'Windows RPC endpoint mapper',
        'description': 'Microsoft RPC exposed externally enables service enumeration and well-known SMB/RPC exploit chains.',
        'attack_vector': 'Enumeration of named pipes; chained exploitation (e.g., MS08-067, MS17-010 family).',
        'mitigation': 'Block 135/137-139/445 at the perimeter; segregate Windows administration to a management VLAN.',
        'references': ['CVE-2017-0144', 'CVE-2008-4250', 'MITRE ATT&CK T1021.002'],
        'severity': 'critical',
    },
    137: {
        'service': 'netbios-ns',
        'class': 'NetBIOS name service',
        'description': 'NetBIOS leaks workgroup/host identity and is the entry point for LLMNR/NBT-NS poisoning attacks.',
        'attack_vector': 'NBT-NS poisoning to capture NTLMv2 hashes (Responder); information disclosure.',
        'mitigation': 'Disable NetBIOS over TCP/IP; block 137-139/tcp+udp; enforce SMB signing.',
        'references': ['CWE-200', 'MITRE ATT&CK T1557.001'],
        'severity': 'high',
    },
    139: {
        'service': 'netbios-ssn',
        'class': 'legacy SMB session',
        'description': 'Pre-SMB2 session service typically associated with legacy Windows file sharing and exploit chains.',
        'attack_vector': 'Null-session enumeration, downgrade to SMBv1, EternalBlue family.',
        'mitigation': 'Disable SMBv1; block 139/445 externally; require Kerberos + SMB signing internally.',
        'references': ['CVE-2017-0144', 'Microsoft KB2696547'],
        'severity': 'critical',
    },
    143: {
        'service': 'imap',
        'class': 'cleartext mail retrieval',
        'description': 'IMAP without TLS exposes credentials and message bodies.',
        'attack_vector': 'Credential capture, mailbox content theft, MITM.',
        'mitigation': 'Use IMAPS (993) only; enforce TLS 1.2+; modern auth (OAuth) instead of basic.',
        'references': ['CWE-319'],
        'severity': 'high',
    },
    161: {
        'service': 'snmp',
        'class': 'device management information disclosure',
        'description': 'SNMPv1/v2c uses community strings (often "public"/"private") in cleartext.',
        'attack_vector': 'Community-string guessing reveals routes, ARP tables, configs; SNMP write community enables config tampering.',
        'mitigation': 'Use SNMPv3 with auth+priv; rotate community strings; restrict to management VLAN; firewall 161/162 externally.',
        'references': ['CWE-521', 'CIS Controls 12.6'],
        'severity': 'high',
    },
    389: {
        'service': 'ldap',
        'class': 'directory enumeration & cleartext bind',
        'description': 'LDAP without StartTLS exposes bind credentials and full directory queries.',
        'attack_vector': 'Anonymous bind enumeration, credential sniffing, LDAP injection.',
        'mitigation': 'Require LDAPS (636) or StartTLS; disable anonymous bind; restrict to internal networks.',
        'references': ['CWE-319', 'Microsoft ADV190023'],
        'severity': 'high',
    },
    445: {
        'service': 'smb',
        'class': 'remote file sharing & RCE chain',
        'description': 'SMB over TCP exposes file shares and is a recurring RCE target.',
        'attack_vector': 'EternalBlue (MS17-010), SMBGhost (CVE-2020-0796), relay attacks against NTLM.',
        'mitigation': 'Block 445/tcp at the perimeter; disable SMBv1; enforce SMB signing and channel binding.',
        'references': ['CVE-2017-0144', 'CVE-2020-0796', 'MITRE ATT&CK T1021.002'],
        'severity': 'critical',
    },
    512: {
        'service': 'rexec',
        'class': 'legacy Berkeley remote shell',
        'description': 'rexec authenticates with cleartext credentials and is universally deprecated.',
        'attack_vector': 'Credential capture; legacy buffer-overflow CVEs.',
        'mitigation': 'Remove rexec/rlogin/rsh; replace with SSH; block 512-514/tcp.',
        'references': ['CVE-1999-0651'],
        'severity': 'critical',
    },
    513: {
        'service': 'rlogin',
        'class': 'legacy trust-based remote login',
        'description': '.rhosts trust files allow passwordless logins from any host that can spoof an address.',
        'attack_vector': 'IP spoofing into the trust list; cleartext session sniffing.',
        'mitigation': 'Decommission; replace with SSH key auth.',
        'references': ['CVE-1999-0651'],
        'severity': 'critical',
    },
    514: {
        'service': 'syslog/rsh',
        'class': 'cleartext logging & legacy shell',
        'description': 'UDP/TCP 514 carries unauthenticated syslog or the rsh remote shell.',
        'attack_vector': 'Log spoofing/forgery; cleartext credentials for rsh.',
        'mitigation': 'Use TLS-protected syslog (RFC 5425) or HTTPS-based log shipping; remove rsh entirely.',
        'references': ['RFC 5425', 'CWE-319'],
        'severity': 'high',
    },
    873: {
        'service': 'rsync',
        'class': 'unauthenticated file sync',
        'description': 'rsync daemon without auth permits anonymous read/write of synced trees.',
        'attack_vector': 'Anonymous module enumeration, data exfiltration, supply-chain tampering.',
        'mitigation': 'Tunnel rsync over SSH; require auth; firewall 873/tcp.',
        'references': ['CWE-306'],
        'severity': 'high',
    },
    1433: {
        'service': 'mssql',
        'class': 'database engine exposed',
        'description': 'Microsoft SQL Server tabular data stream open externally enables credential attacks and SQL injection.',
        'attack_vector': 'sa-account brute-force, xp_cmdshell escalation, lateral movement via linked servers.',
        'mitigation': 'Bind to internal interfaces only; require AAD/Kerberos auth; rotate sa; firewall 1433.',
        'references': ['CWE-269', 'MITRE ATT&CK T1078.001'],
        'severity': 'critical',
    },
    1521: {
        'service': 'oracle-tns',
        'class': 'Oracle TNS Listener',
        'description': 'Oracle Transparent Network Substrate exposes service names and version banners and has a long CVE history.',
        'attack_vector': 'TNS poisoning (CVE-2012-1675), credential brute-force, listener command injection.',
        'mitigation': 'Apply Oracle CPU; enable VALID_NODE_CHECKING; restrict listener to private network.',
        'references': ['CVE-2012-1675'],
        'severity': 'critical',
    },
    2049: {
        'service': 'nfs',
        'class': 'unauthenticated file system export',
        'description': 'NFSv3 without Kerberos relies on UID/GID trust, allowing crafted clients to read or write any export.',
        'attack_vector': 'Squash bypass, UID spoofing, NFS handle replay.',
        'mitigation': 'Use NFSv4 with Kerberos; restrict exports by network; firewall 2049 externally.',
        'references': ['CWE-285'],
        'severity': 'critical',
    },
    2375: {
        'service': 'docker',
        'class': 'unauthenticated Docker API',
        'description': 'Docker daemon socket on 2375 grants root-equivalent container control with no authentication.',
        'attack_vector': 'Container escape, host filesystem mount, cryptominer drop.',
        'mitigation': 'Never expose 2375; use 2376 with mTLS only on management networks; prefer Unix socket + sudo.',
        'references': ['CWE-306', 'MITRE ATT&CK T1610'],
        'severity': 'critical',
    },
    2376: {
        'service': 'docker-tls',
        'class': 'Docker API (TLS)',
        'description': 'Even with TLS, the Docker API equals root on the host and should never be internet-facing.',
        'attack_vector': 'Client certificate theft yields full container/host control.',
        'mitigation': 'Restrict to management VLAN; rotate client certs; prefer SSH+kubectl/docker context.',
        'references': ['CWE-306'],
        'severity': 'high',
    },
    3306: {
        'service': 'mysql',
        'class': 'database engine exposed',
        'description': 'MySQL/MariaDB bound to a public interface enables credential attacks and data exfiltration.',
        'attack_vector': 'Brute-force of root/app users, UDF privilege escalation, replication abuse.',
        'mitigation': 'Bind to 127.0.0.1; require TLS; rotate credentials; firewall 3306; use bastion + tunnel.',
        'references': ['CWE-284', 'CIS MySQL Benchmark'],
        'severity': 'critical',
    },
    3389: {
        'service': 'rdp',
        'class': 'remote desktop',
        'description': 'Remote Desktop is a top ransomware entry vector when exposed externally.',
        'attack_vector': 'Credential spraying, BlueKeep (CVE-2019-0708), session hijack via tscon.',
        'mitigation': 'Never expose RDP to the internet; use Azure Bastion / RDS Gateway; enforce NLA + MFA.',
        'references': ['CVE-2019-0708', 'CISA AA20-302A'],
        'severity': 'critical',
    },
    4444: {
        'service': 'metasploit',
        'class': 'common attacker callback port',
        'description': 'Port 4444 is the default Metasploit Meterpreter listener — its presence on a server is a strong IOC.',
        'attack_vector': 'Reverse-shell beaconing, post-exploitation persistence.',
        'mitigation': 'Treat as an incident; image the host; rotate credentials; involve IR.',
        'references': ['MITRE ATT&CK T1071.001'],
        'severity': 'critical',
    },
    5432: {
        'service': 'postgres',
        'class': 'database engine exposed',
        'description': 'PostgreSQL on a public interface allows credential attacks and data exfiltration.',
        'attack_vector': 'Brute-force, COPY ... FROM PROGRAM (CVE-2019-9193) for RCE, replication abuse.',
        'mitigation': 'Bind to localhost; pg_hba.conf to allow only trusted CIDRs; require TLS; rotate creds.',
        'references': ['CVE-2019-9193'],
        'severity': 'critical',
    },
    5900: {
        'service': 'vnc',
        'class': 'remote desktop',
        'description': 'VNC often ships with weak or no authentication and short password limits.',
        'attack_vector': 'Brute-force, MITM (no TLS by default), session sniffing.',
        'mitigation': 'Tunnel over SSH/VPN; disable on production; use NLA-protected RDP or remote-tools with MFA.',
        'references': ['CWE-307'],
        'severity': 'critical',
    },
    5984: {
        'service': 'couchdb',
        'class': 'document database exposed',
        'description': 'CouchDB admin Futon/Fauxton bound externally has been the source of multiple worms.',
        'attack_vector': 'Admin party (no auth), CVE-2017-12635 / CVE-2022-24706 RCE chains.',
        'mitigation': 'Bind to localhost; require admin auth; patch to latest; firewall 5984.',
        'references': ['CVE-2017-12635', 'CVE-2022-24706'],
        'severity': 'critical',
    },
    6379: {
        'service': 'redis',
        'class': 'in-memory database exposed',
        'description': 'Default Redis has no authentication; the CONFIG command can write SSH keys and trigger RCE.',
        'attack_vector': 'Unauthenticated CONFIG SET + SAVE chain to write authorized_keys; Lua sandbox escapes.',
        'mitigation': 'Bind to 127.0.0.1; set requirepass + ACLs; disable CONFIG; run as non-root; firewall 6379.',
        'references': ['CVE-2022-0543', 'MITRE ATT&CK T1190'],
        'severity': 'critical',
    },
    6667: {
        'service': 'irc',
        'class': 'IRC / common botnet C2',
        'description': 'IRC on standard port is a long-time botnet command-and-control channel.',
        'attack_vector': 'Botnet beaconing, content injection, data exfiltration over IRC privmsg.',
        'mitigation': 'Block 6660-6669/tcp; investigate the listener as a potential C2 channel.',
        'references': ['MITRE ATT&CK T1071.001'],
        'severity': 'high',
    },
    7001: {
        'service': 'weblogic',
        'class': 'Java application server',
        'description': 'Oracle WebLogic exposes T3/IIOP deserialization endpoints with a long RCE history.',
        'attack_vector': 'CVE-2017-10271, CVE-2019-2725, CVE-2020-14882 deserialization → RCE.',
        'mitigation': 'Patch immediately; block 7001/7002 externally; restrict T3 to internal subnets.',
        'references': ['CVE-2020-14882', 'CVE-2019-2725'],
        'severity': 'critical',
    },
    8080: {
        'service': 'http-proxy',
        'class': 'alternate HTTP / admin console',
        'description': 'Port 8080 commonly hosts Tomcat manager, Jenkins, internal admin consoles, or open proxies.',
        'attack_vector': 'Default credentials, Tomcat manager upload-to-RCE, open-proxy abuse, SSRF pivots.',
        'mitigation': 'Authenticate every admin console; remove default creds; firewall externally; HTTPS-only.',
        'references': ['CWE-798', 'OWASP A05:2021'],
        'severity': 'high',
    },
    8443: {
        'service': 'https-alt',
        'class': 'alternate HTTPS / admin console',
        'description': 'Encrypted but still a non-443 listener — typically vendor admin UI with weak access control.',
        'attack_vector': 'Default credentials, self-signed-cert acceptance, console-driven RCE.',
        'mitigation': 'Require enterprise certs + SSO; restrict to management VLAN; rotate vendor defaults.',
        'references': ['OWASP A05:2021'],
        'severity': 'high',
    },
    9200: {
        'service': 'elasticsearch',
        'class': 'search cluster exposed',
        'description': 'Elasticsearch without auth allows full read/write/delete of every index.',
        'attack_vector': 'Mass data exfiltration, ransom-note overwrite, RCE via groovy/painless sandbox in old versions.',
        'mitigation': 'Enable X-Pack/Security; require TLS + RBAC; bind to private interface; firewall 9200.',
        'references': ['CVE-2015-1427', 'CISA AA22-216A'],
        'severity': 'critical',
    },
    11211: {
        'service': 'memcached',
        'class': 'cache exposed / UDP amplification',
        'description': 'UDP/11211 was the source of record-breaking amplification DDoS in 2018; even TCP exposes cached data.',
        'attack_vector': 'UDP amplification DDoS (factor 50,000×), unauthenticated cache poisoning.',
        'mitigation': 'Disable UDP; bind to 127.0.0.1; require SASL auth; firewall 11211.',
        'references': ['CVE-2018-1000115', 'US-CERT TA14-017A'],
        'severity': 'critical',
    },
    27017: {
        'service': 'mongodb',
        'class': 'document database exposed',
        'description': 'MongoDB historically defaulted to no auth, leading to multiple mass-ransom waves.',
        'attack_vector': 'Anonymous read/write, ransom-note insertion, replica-set takeover.',
        'mitigation': 'Enable auth + TLS; bind to private interface; configure RBAC; firewall 27017.',
        'references': ['CISA Alert AA20-006A'],
        'severity': 'critical',
    },
}


def _generic_intel(port: int) -> Dict[str, object]:
    """Fallback intel for any port not in the curated table."""
    if port < 1024:
        bucket = 'well-known system port'
        severity = 'high'
    elif port < 49152:
        bucket = 'registered service port'
        severity = 'high'
    else:
        bucket = 'dynamic / ephemeral port'
        severity = 'medium'
    return {
        'service': None,
        'class': 'policy violation — non-443 exposure',
        'description': (
            f'TCP/{port} ({bucket}) is reachable. Enterprise policy permits HTTPS/443 only; any '
            'other open or filtered port is a potential lateral-movement entry point and must be '
            'closed, justified, or moved behind a bastion.'
        ),
        'attack_vector': (
            'Adversaries fingerprint the listening service and pivot via known CVEs, default '
            'credentials, or protocol-level weaknesses.'
        ),
        'mitigation': (
            'Close the port at the host firewall and the perimeter, or document the exception '
            'with compensating controls (mTLS, allow-list, MFA, segmentation).'
        ),
        'references': ['CWE-1188', 'CIS Controls 4.5', 'NIST 800-53 SC-7'],
        'severity': severity,
    }


def lookup(port: int) -> Dict[str, object]:
    return PORT_INTEL.get(port) or _generic_intel(port)


def serialize_refs(refs) -> str:
    if not refs:
        return ''
    if isinstance(refs, str):
        return refs
    return '; '.join(str(r) for r in refs)
