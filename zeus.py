# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =  ZEUUS THREAT PROTECTION SYSTEM =
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
import socket
import threading
import time
import subprocess
import os
import ipaddress
import re
import requests
import tempfile
import shutil
from scapy.all import *
from collections import defaultdict

import subprocess
# ANTI THREAT CONFIG
# Globals for tracking connection patterns
connection_attempts = defaultdict(list)  # Tracks attempts {IP: [timestamps]}
BAN_THRESHOLD = 20  # Threshold for connection attempts in a short time
TIME_WINDOW = 10  # Time window (in seconds) for detecting port scanning

log_file_path = "/var/log/apache2/access.log"  # Replace with your log file path
banned_ips_log = "banned_ips.txt"  # File to track already banned IPs

# Regex patterns for detecting suspicious requests
suspicious_patterns = [
    # File inclusion and RCE attempts
    r"(GET|POST) .*?/vendor/phpunit/.*?",  # Attempts to exploit PHPUnit
    r"(GET|POST) .*?/\.env",               # Access to .env files
    r"(GET|POST) .*?auto_prepend_file",    # PHP inclusion attacks
    r"(GET|POST) .*?/index\.php\?s=",      # PHP application RCE
    r"(GET|POST) .*?eval-stdin.php",       # PHPUnit eval exploits
    r"(GET|POST) .*?/phpinfo\.php",        # Probing for PHP configuration
    r"(GET|POST) .*?/config\.php",         # Access to config files
    r"(GET|POST) .*?\.php\?cmd=",          # Command execution via GET/POST
    r"(GET|POST) .*?/wp-config\.php",      # WordPress config file access
    r"(GET|POST) .*?/system\.ini",         # Probing for system.ini files

    # Directory traversal and LFI attempts
    r"(GET|POST) .*?\.\./\.\./",           # Directory traversal patterns
    r"(GET|POST) .*?/etc/passwd",          # Access to Linux password file
    r"(GET|POST) .*?/proc/self/environ",   # Accessing environment variables
    r"(GET|POST) .*?/logs/error\.log",     # Attempting to access error logs
    r"(GET|POST) .*?/var/lib/mysql/.*?",   # Probing for MySQL database files

    # SQL injection attempts
    r"(GET|POST) .*?union\s+select",       # SQL UNION injection
    r"(GET|POST) .*?\bselect\b.*?\bfrom\b", # Basic SQL SELECT injection
    r"(GET|POST) .*?\bunion\b.*?\bselect\b", # UNION SELECT SQL injection
    r"(GET|POST) .*?information_schema",  # Probing the information schema
    r"(GET|POST) .*?\bconcat\b.*?\(",     # SQL CONCAT function abuse

    # XSS (Cross-Site Scripting) attempts
    r"(GET|POST) .*?<script>.*?</script>", # Simple script injection
    r"(GET|POST) .*?onmouseover=.*?",      # XSS with event handlers
    r"(GET|POST) .*?javascript:.*?",       # JS protocol injection
    r"(GET|POST) .*?<img src=.*?onerror=", # XSS with image onerror
    r"(GET|POST) .*?document.cookie",      # XSS targeting cookies

    # Common backdoors and webshells
    r"(GET|POST) .*?c99\.php",             # Common PHP webshell
    r"(GET|POST) .*?r57\.php",             # Common PHP webshell
    r"(GET|POST) .*?cmd\.php",             # Simple PHP shell
    r"(GET|POST) .*?shell\.php",           # General webshell pattern
    r"(GET|POST) .*?upload\.php",          # Exploiting uploaders

    # HTTP header injection
    r"(GET|POST) .*?\bReferer:.*?\n.*?Content-Type:.*?multipart/", # Header manipulation
    r"(GET|POST) .*?\bHost:.*?\n.*?\bX-Forwarded-For:",            # Host spoofing

    # Exploitation of CMS and frameworks
    r"(GET|POST) .*?/wp-admin/admin-ajax\.php", # WordPress AJAX exploitation
    r"(GET|POST) .*?/drupal\.php",              # Drupal-specific exploits
    r"(GET|POST) .*?/joomla\.php",              # Joomla-specific exploits

    # Others
    r"(GET|POST) .*?\bbase64_decode\(.*?\)",    # Base64 decoding in URLs
    r"(GET|POST) .*?\bassert\(.*?\)",           # PHP assert() abuse
    r"(GET|POST) .*?\bsystem\(.*?\)",           # PHP system() abuse
    r"(GET|POST) .*?\bpopen\(.*?\)",            # PHP popen() abuse
]

# Load banned words from a file or define them here
BANNED_WORDS = ["malware", "exploit", "hack", "admin", "/login", ".git", "../", "/etc", "passwd", "alert", "/bin/sh", "phpunit", "eval", "auto_prepend_file", "call_user_func_array", "think\\app", "pearcmd", ".%2e", "%ADd", "LICENSE", "backup", "workspace", "drupal", "cms", "laravel", "zend", "call_user_func", "php://input", "metasploit", "nmap", "sqlmap", "hydra", "aircrack-ng", "john", "msfconsole", "netcat", "nc", "wifite", "ettercap", "dnsenum", "nikto", "recon-ng", "beEF", "burpsuite", "proxychains", "wpscan", "dirb", "gobuster", "maltego", "setoolkit", "social-engineer-toolkit", "smbclient", "mshta", "mimikatz", "crackmapexec", "responder"]
OWASP_TOP_10_PATTERNS = [
    r"union.*select.*from",  # SQL Injection (basic UNION SELECT)
    r"select.*from.*information_schema.tables",  # SQL Injection (Schema Disclosure)
    r"'<script>.*</script>'",  # XSS (Cross-site Scripting)
    r"eval\(",  # Remote Code Execution
    r"cmd\s+|bash\s+|sh\s+",  # Command injection (Bash/Command execution)
    r"/\*\s*.+?\s*\*/",  # SQL Injection (Comments for obfuscation)
    r"<!--.*?-->",  # XSS (HTML comments used for hiding code)
    r"base64_encode\(",  # Base64 encoding (obfuscation attempt)
    r"\/etc\/passwd",  # File inclusion attempt (etc/passwd)
    r"file\:\/\/",  # File inclusion attempt
    r"union.*select.*from",  # SQL Injection (basic UNION SELECT)
    r"select.*from.*information_schema.tables",  # SQL Injection (Schema Disclosure)
    r"'<script>.*</script>'",  # XSS (Cross-site Scripting)
    r"eval\(",  # Remote Code Execution
    r"cmd\s+|bash\s+|sh\s+",  # Command injection (Bash/Command execution)
    r"/\*\s*.+?\s*\*/",  # SQL Injection (Comments for obfuscation)
    r"<!--.*?-->",  # XSS (HTML comments used for hiding code)
    r"base64_encode\(",  # Base64 encoding (obfuscation attempt)
    r"\/etc\/passwd",  # File inclusion attempt (etc/passwd)
    r"file\:\/\/",  # File inclusion attempt
    r"<script>.*?</script>",  # XSS (Cross-site Scripting)
    r"(<iframe.*?>.*?</iframe>)",  # XSS (iframe injection)
    r"(<object.*?>.*?</object>)",  # XSS (object tag injection)
    r"(<embed.*?>.*?</embed>)",  # XSS (embed tag injection)
    r"(<applet.*?>.*?</applet>)",  # XSS (applet tag injection)
    r"(<form.*?>.*?</form>)",  # XSS (form injection)
    r"insert\s+into\s+.*\s+values\s*\(",  # SQL Injection (INSERT statement)
    r"select\s+\*\s+from\s+.*\s+where\s+",  # SQL Injection (SELECT with WHERE)
    r"update\s+.*\s+set\s+.*\s+where\s+",  # SQL Injection (UPDATE with WHERE)
    r"delete\s+from\s+.*\s+where\s+",  # SQL Injection (DELETE with WHERE)
    r"drop\s+table\s+",  # SQL Injection (DROP TABLE)
    r"drop\s+database\s+",  # SQL Injection (DROP DATABASE)
    r"show\s+tables",  # SQL Injection (SHOW TABLES)
    r"show\s+databases",  # SQL Injection (SHOW DATABASES)
    r"select\s+\*\s+from\s+mysql.user",  # SQL Injection (MySQL user table)
    r"select\s+\*\s+from\s+pg_user",  # SQL Injection (Postgres user table)
    r"select\s+\*\s+from\s+information_schema.columns",  # SQL Injection (Schema Disclosure)
    r"select\s+\*\s+from\s+mysql.db",  # SQL Injection (MySQL database table)
    r"select\s+password\s+from\s+mysql.user",  # SQL Injection (MySQL password table)
    r"or\s+1=1",  # SQL Injection (Common OR-based bypass)
    r"or\s+1\=1\s*--",  # SQL Injection (OR-based bypass with comment)
    r"and\s+1=1",  # SQL Injection (AND-based bypass)
    r"or\s+1=0\s*--",  # SQL Injection (OR-based false condition)
    r"select\s+password\s+from\s+.*\s*where\s+username\s*=\s*'[^']*'",  # SQL Injection (Password Extract)
    r"select.*from.*information_schema.columns.*where.*table_name.*",  # SQL Injection (Information Schema Disclosure)
    r"union.*select.*null.*from",  # SQL Injection (NULL-based Union Select)
    r"select\s+\*\s+from\s+.*\s+group\s+by",  # SQL Injection (Group by Clause)
    r"\/bin\/sh",  # Command Injection (Unix shell)
    r"\/usr\/bin\/bash",  # Command Injection (Bash shell)
    r"exec\(",  # Remote Code Execution (exec)
    r"system\(",  # Remote Code Execution (system)
    r"passthru\(",  # Remote Code Execution (passthru)
    r"shell_exec\(",  # Remote Code Execution (shell_exec)
    r"eval\(",  # Remote Code Execution (eval)
    r"phpinfo\(",  # Information Disclosure (phpinfo)
    r"file_get_contents\(",  # File Inclusion / Read File
    r"include\(",  # PHP include (Local File Inclusion)
    r"require\(",  # PHP require (Local File Inclusion)
    r"include_once\(",  # PHP include_once (Local File Inclusion)
    r"require_once\(",  # PHP require_once (Local File Inclusion)
    r"ftp:\/\/",  # Potential File Inclusion (FTP)
    r"file:\/\/",  # Potential File Inclusion (file://)
    r"http:\/\/",  # Potential File Inclusion (HTTP)
    r"\/dev\/null",  # File Inclusion / Path Traversal
    r"\.\.\/",  # Directory Traversal
    r"\/etc\/shadow",  # File Inclusion Attempt (shadow file)
    r"\/proc\/self\/environ",  # File Inclusion Attempt (environment variables)
    r"\/proc\/[0-9]+\/fd\/",  # File Inclusion Attempt (process file descriptors)
    r"\/etc\/hosts",  # File Inclusion Attempt (hosts file)
    r"\/etc\/group",  # File Inclusion Attempt (group file)
    r"base64_decode\(",  # Potential obfuscation (Base64 decoding)
    r"gopher:\/\/",  # Potential File Inclusion (gopher protocol)
    r"php:\/\/",  # Potential File Inclusion (PHP protocol)
    r"mongodb:\/\/",  # Database connection (MongoDB)
    r"sqlmap",  # SQL Injection Tool (sqlmap)
    r"nmap",  # Network Scanner (nmap)
    r"hydra",  # Brute Force Tool (hydra)
    r"metasploit",  # Exploit Framework (Metasploit)
    r"beef",  # Social Engineering Framework (BeEF)
    r"nikto",  # Web Scanner (Nikto)
    r"wpscan",  # WordPress Scanner (WPScan)
    r"dirb",  # Directory Buster (dirb)
    r"gobuster",  # Directory Buster (Gobuster)
    r"burpsuite",  # Proxy/Interception Tool (Burp Suite)
    r"recon-ng",  # Reconnaissance Framework (Recon-NG)
    r"social-engineer-toolkit",  # Social Engineering Framework (SET)
    r"smbclient",  # SMB Protocol Tool (SMBClient)
    r"msfconsole",  # Metasploit Console
    r"mimikatz",  # Post-exploitation Tool (Mimikatz)
    r"crackmapexec",  # Lateral Movement Tool (CrackMapExec)
    r"aircrack-ng",  # Wireless Cracking Tool (Aircrack-ng)
    r"ettercap",  # MITM Tool (Ettercap)
    r"john",  # Password Cracking Tool (John the Ripper)
    r"recon-ng",  # Reconnaissance Framework (Recon-NG)
    r"beEF",  # Exploit Framework (BeEF)
    r"proxychains",  # Proxy Tool (Proxychains)
    r"mshta",  # HTA Execution Tool (MSHTA)
    r"mimikatz",  # Post-exploitation Tool (Mimikatz)
    r"crackmapexec",  # SMB/SMBv2 tool (CrackMapExec)
    r"responder",  # Lateral Movement Tool (Responder)
    r"lfi",  # Local File Inclusion (LFI) detection
    r"rfi",  # Remote File Inclusion (RFI) detection
    r"xxe",  # XML External Entity Injection (XXE)
    r"outbound.*cmd",  # Outbound Command Injection
    r"stager.*\.php",  # PHP Stager (Payload)
    r"webshell",  # Web Shell Detection
    r"reverse\s*shell",  # Reverse Shell Command
    r"persistence\s*mechanism",  # Persistence Mechanism (Persistence)
    r"debugger\s*engine",  # Debugging Tools (engine)
    r"export\s*PATH",  # Environmental Variable Modification (PATH)
    r"wget\s*",  # Remote File Download via wget
    r"curl\s*",  # Remote File Download via curl
]
# Configuration
IP_LIST_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IPSET_NAME = "blocked_ips"
TOR_EXIT_LIST_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip="

# SSL SHIT:
#ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
#ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Proxy configuration
PROXY_HOST = "0.0.0.0"      # Listen on all interfaces
PROXY_PORT = 23             # Proxy listens on port 80
APACHE_HOST = "127.0.0.1"   # Apache server address (localhost)
APACHE_PORT = 1989          # Apache server port
# ---------------------------
def print_banner():
    banner = '''
      ::::::::: :::::::::: :::    ::: :::    :::  ::::::::               ::::::::::: ::::::::: 
          :+:  :+:        :+:    :+: :+:    :+: :+:    :+:                  :+:     :+:    :+: 
        +:+   +:+        +:+    +:+ +:+    +:+ +:+                         +:+     +:+    +:+  
      +#+    +#++:++#   +#+    +:+ +#+    +:+ +#++:++#++ +#++:++#++:++    +#+     +#++:++#+    
    +#+     +#+        +#+    +#+ +#+    +#+        +#+                  +#+     +#+           
  #+#      #+#        #+#    #+# #+#    #+# #+#    #+#                  #+#     #+#            
######### ##########  ########   ########   ########                   ###     ###              
    '''
    print(banner)

# ---------------------------
# Load the malicious IP list from the external source
def load_malicious_ips():
    try:
        response = requests.get(IP_LIST_URL)
        if response.status_code == 200:
            return set(response.text.splitlines())
    except Exception as e:
        print(f"Error loading malicious IP list: {e}")
    return set()

# Load malicious IP list at startup
malicious_ips = load_malicious_ips()

# Function to check if a packet is suspicious
def is_suspicious(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        tcp_dport = packet[TCP].dport
        payload = str(packet[TCP].payload)  # Get the packet payload as a string

        # Check for persistent connections (port scanning or frequent access)
        current_time = time.time()
        if ip_src not in connection_attempts:
            connection_attempts[ip_src] = []
        connection_attempts[ip_src].append(current_time)

        # Remove old timestamps outside the time window
        connection_attempts[ip_src] = [
            t for t in connection_attempts[ip_src] if current_time - t <= TIME_WINDOW
        ]

        # Check against malicious IP list
        if ip_src in malicious_ips:
            print(f"Detected malicious IP from list: {ip_src}")
            return ip_src

        # Check if the payload contains banned words
        for word in BANNED_WORDS:
            if word in payload.lower():
                print(f"Detected banned content in packet from {ip_src}: {word}")
                return ip_src

        # Check for OWASP Top 10 vulnerabilities
        for pattern in OWASP_TOP_10_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                print(f"Detected potential OWASP Top 10 vulnerability in packet from {ip_src}: {pattern}")
                return ip_src

    return None

# Function to ban an IP using ipset
def ban_ip(ip):
    try:
        subprocess.run(["sudo", "ipset", "add", "blocked_ips", ip], check=True)
        print(f"Banned IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"IP {ip} is already banned or an error occurred.")

# Compile regex patterns for performance
compiled_patterns = [re.compile(pattern) for pattern in suspicious_patterns]

def parse_logs_and_ban(log_file, banned_ips_file):
    suspicious_ips = set()  # Store unique suspicious IPs
    banned_ips = set()      # Store already banned IPs

    # Load already banned IPs to avoid duplicate bans
    try:
        with open(banned_ips_file, "r") as file:
            banned_ips = set(file.read().splitlines())
    except FileNotFoundError:
        pass  # First run, no banned IPs yet

    # Parse log file
    with open(log_file, "r") as logs:
        for line in logs:
            for pattern in compiled_patterns:
                if pattern.search(line):
                    # Extract IP address (assumes IP is the first part of the line)
                    ip_match = re.match(r"(\d{1,3}\.){3}\d{1,3}", line)
                    if ip_match:
                        suspicious_ips.add(ip_match.group(0))
                    break  # No need to check other patterns for this line

    # Ban new suspicious IPs
    new_bans = suspicious_ips - banned_ips
    for ip in new_bans:
        ban_ip(ip)

    # Update the banned IPs file
    with open(banned_ips_file, "a") as file:
        for ip in new_bans:
            file.write(ip + "\n")

    print(f"Total banned IPs: {len(banned_ips | suspicious_ips)}")
    print(f"Newly banned IPs: {len(new_bans)}")

# Function to check if an IP is local (e.g., router, DNS, etc.)
def is_local_ip(ip):
    # Define ranges of local IPs (private IP address ranges)
    local_ip_ranges = [
        "10.0.0.0/8",  # 10.x.x.x range
        "172.16.0.0/12",  # 172.16.x.x to 172.31.x.x range
        "192.168.0.0/16",  # 192.168.x.x range
    ]
    
    try:
        # Convert the given IP to an IPv4 address object
        ip_obj = ipaddress.IPv4Address(ip)
        
        # Check if the IP falls within any of the local IP ranges
        for local_range in local_ip_ranges:
            if ip_obj in ipaddress.IPv4Network(local_range):
                return True
    except ValueError:
        pass  # In case of an invalid IP address
    return False

# Packet handler function
def packet_callback(packet):
    # Check if the packet has the required layers
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Get source IP address from packet
        
        suspicious_ip = is_suspicious(packet)  # Assume this function checks suspicious behavior
        if suspicious_ip and not is_local_ip(ip_src):  # Check if the IP is not local
            print(f"Suspicious packet detected from {ip_src}. Banning...")
            ban_ip(suspicious_ip)  # Function to ban the IP (you should define it elsewhere)

# ---------------------------
def command_handling():
    """Perform network protection scanning by detecting suspicious processes."""
    print("Performing command protection scanning...")

    # Patterns for suspicious processes
    SUSPICIOUS_PATTERNS = [
        "python.*-c.*socket",  # Python reverse shell pattern
        "bash.*-i",           # Bash interactive shell
        "nc.*-e",             # Netcat reverse shell
        "sh.*-c.*exec",       # Shell executing harmful commands
        "perl.*-M.*Socket",   # Perl reverse shell
        "ruby.*socket",       # Ruby reverse shell
        "php.*exec",          # PHP shell
        "powershell.*-nop",   # PowerShell reverse shell
        "mshta.*http",        # MSHTA executing remote scripts
        "wget.*http",         # wget downloading malicious files
        "curl.*http",         # curl downloading malicious files
    ]

    try:
        # Get a list of running processes
        processes = subprocess.check_output(["ps", "aux"], text=True)

        # Check for suspicious processes
        for line in processes.splitlines():
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    print(f"Suspicious process detected: {line}")
                    # Optionally, take action like logging or killing the process
                    pid = int(line.split()[1])  # Extract PID from process details
                    print(f"Attempting to kill process with PID: {pid}")
                    try:
                        os.kill(pid, 9)  # Kill the process forcefully
                        print(f"Process {pid} terminated.")
                    except Exception as e:
                        print(f"Failed to terminate process {pid}: {e}")
    except Exception as e:
        print(f"Error while scanning processes: {e}")
    """Perform network protection scanning by detecting suspicious processes."""
    print("Performing network protection scanning...")

    # Patterns for suspicious processes, including reverse shells and malicious commands
    SUSPICIOUS_PATTERNS2 = [
        r"bash\s+-i\s+>&\s+/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+\s+0>&1",  # Bash reverse shell pattern 1
        r"0<&196;exec\s+196<>/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+;\s+sh\s+<&196\s+>&196\s+2>&196",  # Bash reverse shell pattern 2
        r"/bin/bash\s+-l\s+>\s+/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+\s+0<&1\s+2>&1",  # Bash reverse shell pattern 3
        r"perl\s+-e\s+'use\s+Socket;\$i=\"\d+\.\d+\.\d+\.\d+\";\$p=\d+;.*?exec\(\"/bin/sh\s+-i\"\);",  # Perl reverse shell
        r"perl\s+-MIO\s+-e\s+'\$p=fork;exit,if\(\$p\);.*?system\$_\s+while<>;",  # Perl IO::Socket reverse shell
        r"python\s+-c\s+'import\s+socket,os,pty;.*?pty.spawn\(\"/bin/sh\"\)",  # Python reverse shell with pty.spawn
        r"python\s+-c\s+'import\s+socket,subprocess,os;.*?subprocess\.call\(\[\"/bin/sh\",\"-i\"\]\)",  # Python reverse shell with subprocess
        r"python\s+-c\s+'import\s+socket,subprocess;.*?subprocess\.call\(\[\"/bin/sh\",\"-i\"\].*?\)",  # Python reverse shell (alternative subprocess)
        r"python\s+-c\s+'import\s+socket,subprocess.*?os\.dup2.*?pty.spawn",  # Python with os.dup2 and pty.spawn
    ]

    try:
        # Get a list of running processes
        processes = subprocess.check_output(["ps", "aux"], text=True)

        # Check for suspicious processes
        for line in processes.splitlines():
            for pattern in SUSPICIOUS_PATTERNS2:
                if re.search(pattern, line, re.IGNORECASE):
                    print(f"Suspicious process detected: {line}")
                    # Extract PID and attempt to terminate the process
                    try:
                        pid = int(line.split()[1])  # Extract PID from process details
                        print(f"Attempting to kill process with PID: {pid}")
                        os.kill(pid, 9)  # Kill the process forcefully
                        print(f"Process {pid} terminated.")
                    except Exception as e:
                        print(f"Failed to terminate process {pid}: {e}")
    except Exception as e:
        print(f"Error while scanning processes: {e}")

def network_behaves ():
    print ("testing network behaviour for weird stuff");
    print("Starting network sniffer...")
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("Stopping sniffer...")

def suricata_addon ():
	print ("analyze suricatas output for IPS defense");

def check_ipset_installed():
    """Check if ipset is installed."""
    if shutil.which("ipset") is None:
        print("ipset is not installed. Please install it and try again.")
        exit(1)

def create_or_reset_ipset(ipset_name):
    """Create or reset the ipset list."""
    print(f"Creating or resetting ipset list: {ipset_name}...")
    subprocess.call(["sudo", "ipset", "destroy", ipset_name], stderr=subprocess.DEVNULL)
    subprocess.call(["sudo", "ipset", "create", ipset_name, "hash:ip", "-exist"])

def fetch_ip_list(url):
    """Fetch the IP list from the URL."""
    print(f"Fetching IP list from {url}...")
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to download IP list. Exiting.")
        exit(1)
    return response.text

def process_ip_list(ip_list, ipset_name):
    """Process the IP list for bulk insertion."""
    print("Processing IP list for bulk insertion...")
    ip_lines = [
        f"add {ipset_name} {line.split()[0]}"
        for line in ip_list.splitlines()
        if line.strip() and not line.startswith("#") and line[0].isdigit()
    ]
    return ip_lines

def load_ips_to_ipset(ip_lines, ipset_name):
    """Load IPs into ipset in bulk."""
    print("Loading IPs into ipset in bulk...")
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(f"create {ipset_name} hash:ip family inet hashsize 1024 maxelem 65536\n".encode())
        temp_file.write("\n".join(ip_lines).encode())
        temp_file_path = temp_file.name

    subprocess.call(["sudo", "ipset", "restore"], stdin=open(temp_file_path))
    os.remove(temp_file_path)

def add_iptables_rule(ipset_name):
    """Add iptables rule to block IPs in ipset."""
    print(f"Adding iptables rule to block IPs in ipset list: {ipset_name}...")
    rule_exists = subprocess.call(
        ["sudo", "iptables", "-C", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"],
        stderr=subprocess.DEVNULL
    ) == 0
    if not rule_exists:
        subprocess.call(["sudo", "iptables", "-I", "INPUT", "-m", "set", "--match-set", ipset_name, "src", "-j", "DROP"])

def block_tor_exit_nodes(ipset_name):
    """Fetch and block Tor exit nodes."""
    print("Fetching Tor exit node IPs...")
    public_ip = requests.get("https://icanhazip.com").text.strip()
    tor_exit_list_url = f"{TOR_EXIT_LIST_URL}{public_ip}"
    response = requests.get(tor_exit_list_url)
    if response.status_code == 200:
        tor_ips = [line.strip() for line in response.text.splitlines() if line and not line.startswith("#")]
        for ip in tor_ips:
            subprocess.call(["sudo", "ipset", "-q", "add", ipset_name, ip])

def handle_client(client_socket):
    """Handles communication between the client and Apache."""
    try:
        # Retrieve the client's IP address
        client_ip = client_socket.getpeername()[0]

        # Connect to the Apache server
        apache_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        apache_socket.connect((APACHE_HOST, APACHE_PORT))

        # Wrapper function for forwarding data while inspecting packets
        def forward_with_inspection(source, destination):
            try:
                while True:
                    # Receive data from the source
                    data = source.recv(4096)
                    if not data:
                        break
                    
                    # Create a mock packet for inspection
                    packet = IP(src=client_ip) / TCP(dport=APACHE_PORT) / data
                    
                    # Check if the packet is suspicious
                    suspicious_ip = is_suspicious(packet)
                    if suspicious_ip:
                        print(f"[ALERT] Evil packet detected from {suspicious_ip}. Banning IP...")
                        ban_ip(suspicious_ip)
                        break  # Stop forwarding data for this connection

                    # Forward the data to the destination
                    destination.sendall(data)
            except Exception as e:
                print(f"Error during forwarding: {e}")
            finally:
                source.close()
                destination.close()

        # Start threads for bi-directional data forwarding with inspection
        client_to_apache = threading.Thread(target=forward_with_inspection, args=(client_socket, apache_socket))
        apache_to_client = threading.Thread(target=forward_with_inspection, args=(apache_socket, client_socket))

        client_to_apache.start()
        apache_to_client.start()

        client_to_apache.join()
        apache_to_client.join()
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()
        apache_socket.close()

def forward_data(source, destination):
    """Forwards data from source to destination."""
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except Exception as e:
        print(f"Connection error: {e}")

def basic_block_defense ():
    check_ipset_installed()
    create_or_reset_ipset(IPSET_NAME)
    ip_list = fetch_ip_list(IP_LIST_URL)
    ip_lines = process_ip_list(ip_list, IPSET_NAME)
    load_ips_to_ipset(ip_lines, IPSET_NAME)
    add_iptables_rule(IPSET_NAME)
    block_tor_exit_nodes("tor")

    print("All IPs have been loaded into the ipset list and blocked.")

def start_sniffer_thread():
    sniffer_thread = threading.Thread(target=network_behaves)
    sniffer_thread.start()  # Starts the thread

def periodic_task():
    """Run the command_handling function every 5 minutes."""
    while True:
        command_handling()
        parse_logs_and_ban(log_file_path, banned_ips_log)
        # monitor_log()
        time.sleep(5)  # Sleep for 5 minutes (300 seconds)

def main():
    print_banner()
    print ("[.:.] - ZEUUS THREAT PROTECTION STARTED...")
    # PROTECTION FOR THE BASIC FIREWALL:
    basic_block_defense ()
    start_sniffer_thread()
    print("Main thread is free to do other tasks...")
    print("Starting command handling protection...")
    # Create and start the thread
    scan_thread = threading.Thread(target=periodic_task)
    scan_thread.daemon = True  # Ensure the thread exits when the main program exits
    scan_thread.start()
    
    print("starting the proxy....")
    """Starts the proxy server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow socket reuse
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(5)

    print(f"Proxy listening on {PROXY_HOST}:{PROXY_PORT}, forwarding to {APACHE_HOST}:{APACHE_PORT}")
    try:
        while True:
            client_socket, addr = server.accept()
            print(f"Incoming connection from {addr}")
            # Handle each connection in a separate thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()

    except KeyboardInterrupt:
        print("Shutting down proxy.")
        server.close()


if __name__ == "__main__":
    main()