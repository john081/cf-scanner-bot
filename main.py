import socket
import urllib.request
import ipaddress
import time
import random
from concurrent.futures import ThreadPoolExecutor
import ssl
import threading
import re
import websocket
import os
import sys
from io import StringIO

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("dnspython not installed - MX checks disabled")

from flask import Flask, request, abort
import telebot
from telebot import types

# ==================== CLOUDFLARE IP RANGES (December 2025) ====================
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:8100::/32",
    "2405:b500::/32", "2a06:98c0::/29", "2c0f:f248::/32"
]

cf_networks = [ipaddress.ip_network(net) for net in CF_RANGES]

def is_cloudflare_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in cf_networks)
    except:
        return False

BYPASS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

def detect_web_server_from_headers(headers):
    server = headers.get('Server', '').strip()
    if server:
        return server
    powered = headers.get('X-Powered-By', '')
    if powered:
        return powered
    via = headers.get('Via', '')
    if via:
        return f"Proxy/Via: {via}"
    return None

def raw_server_banner(ip, port=443, use_ssl=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 100 * 1024: break
        s.close()

        if not response:
            return None

        header_part = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
        headers = {}
        lines = header_part.splitlines()
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        return detect_web_server_from_headers(headers)
    except:
        return None

def fingerprint_server(ip):
    banner = raw_server_banner(ip, 443, True)
    if banner:
        return banner
    banner = raw_server_banner(ip, 80, False)
    if banner:
        return banner
    return "Unknown / Header Stripped"

def fetch_page(host):
    status_code = None
    title = "No response"
    headers = {}
    is_rate_limited = False
    rate_limit_reason = ""
    bypassed_403 = False
    detected_server = None

    for scheme in ["https", "http"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"}
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                status_code = resp.code
                headers = dict(resp.headers)
                detected_server = detect_web_server_from_headers(headers)
                data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:150]
                break
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(getattr(e, 'headers', {}))
            detected_server = detect_web_server_from_headers(headers)
            title = "Access Denied / Blocked"
        except:
            continue

    if status_code in [403, 401, 429, 503]:
        random.shuffle(BYPASS_USER_AGENTS)
        for ua in BYPASS_USER_AGENTS[:10]:
            for scheme in ["https", "http"]:
                try:
                    extra_headers = {
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive"
                    }
                    req = urllib.request.Request(f"{scheme}://{host}", headers=extra_headers)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                        if resp.code == 200:
                            status_code = 200
                            headers = dict(resp.headers)
                            detected_server = detect_web_server_from_headers(headers)
                            data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                            m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                            if m:
                                title = m.group(1).strip()[:150]
                            bypassed_403 = True
                            break
                except:
                    continue
            if bypassed_403:
                break

    if any(k in title.lower() for k in ["attention required", "checking your browser", "captcha", "ray id"]):
        is_rate_limited = True
        rate_limit_reason = "Cloudflare Challenge"

    return {
        "status": status_code,
        "title": title,
        "headers": headers,
        "limited": is_rate_limited,
        "reason": rate_limit_reason,
        "bypassed_403": bypassed_403,
        "server": detected_server
    }

def test_raw_get_root(ip, is_https=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, 443))
        else:
            s.connect((ip, 80))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
        s.close()
        if response:
            head = response.split(b"\r\n\r\n")[0].decode(errors='ignore')
            if "200" in head.splitlines()[0] or "301" in head.splitlines()[0] or "302" in head.splitlines()[0]:
                return True
        return False
    except:
        return False

def test_websocket_exact(ip):
    for scheme in ["wss", "ws"]:
        url = f"{scheme}://{ip}/"
        try:
            ws = websocket.WebSocket()
            ws.settimeout(10)
            custom_headers = [
                ("Host", ip),
                ("Connection", "Keep-Alive"),
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket")
            ]
            ws.connect(url, custom_header=custom_headers)
            ws.close()
            return True, scheme.upper()
        except:
            continue
    return False, None

def scan_ports(ip):
    ports = [21, 22, 80, 443, 8080, 8443, 2222, 3389, 3306, 5432, 25, 587]
    open_ports = []
    def try_port(p):
        try:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(try_port, ports)
    return sorted(open_ports)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_mx(domain):
    if not HAS_DNS: return []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        leaks = []
        for rdata in answers:
            mail = str(rdata.exchange).rstrip('.')
            ip = resolve_host(mail)
            if ip:
                leaks.append((mail, ip))
        return leaks
    except:
        return []

# ==================== EXPANDED SUBDOMAIN WORDLIST (352 entries) ====================
SUBDOMAIN_WORDLIST = [
    "direct","direct-connect","origin","mail","webmail","smtp","pop","pop3","imap","ftp","cpanel","whm","webdisk",
    "admin","portal","dev","staging","test","beta","api","app","mobile","status","dashboard","login","secure",
    "vpn","remote","ssh","bastion","db","mysql","panel","server","node","backup","ns1","ns2","autoconfig",
    "autodiscover","mx","owa","exchange","intranet","git","jenkins","docker","k8s","monitor","grafana",
    "prometheus","kibana","elasticsearch","redis","rabbitmq","sentry","www","cdn","assets","static","media",
    "origin-www","origin-web","direct-www","bypass","legacy","old","new","proxy","edge","cf","cloudflare",
    "internal","private","hidden","exposed","leak","raw","direct2","origin2","direct-connect2","origin-prod",
    "development","qa","qc","uat","preprod","pre-prod","sandbox","demo","preview","alpha","rc","release",
    "staging2","staging-2","staging3","test2","dev2","dev3","stage","stg","prod-test","integration","int",
    "ci","cd","build","canary","feature","experiment","lab","labs","research","poc",
    "api2","api-v1","api-v2","api-v3","api-dev","api-staging","api-test","graphql","rest","v1","v2","v3","v4",
    "m","mobile-api","ios","android","mobileapp","app-api","gateway-api","external-api","internal-api",
    "administrator","admins","superadmin","control","manage","management","cp","controlpanel","user","users",
    "account","accounts","my","myaccount","client","clients","customer","customers","partner","partners",
    "vendor","vendors","employee","employees","staff","team","hr","recruit","sales","marketing",
    "blog","shop","store","ecommerce","cart","checkout","forum","forums","community","wiki","docs","doc",
    "help","support","ticket","tickets","zendesk","jira","confluence","bitbucket","gitlab","github",
    "sonar","sonarqube","nexus","artifactory","vault","consul","nomad","traefik","nginx","haproxy",
    "lb","loadbalancer","proxy1","proxy2","gateway","router","firewall","waf","ids","ips",
    "metrics","stats","analytics","log","logs","logging","splunk","newrelic","datadog","zabbix","nagios",
    "health","healthcheck","ping","uptime","statuspage","graylog","alert","alerts","ops","observability",
    "postgres","postgresql","mongo","mongodb","couch","couchdb","cassandra","memcached","cache","redis-cache",
    "db1","db2","db3","master","slave","replica","read-replica","shard","cluster",
    "email","zimbra","roundcube","squirrelmail","horde","outlook","webaccess","activesync","mailman",
    "ssl","vpn2","ipsec","openvpn","wireguard","fortigate","paloalto","cisco","juniper","mfa","auth",
    "files","upload","uploads","download","downloads","share","shares","images","img","video","videos",
    "assets2","cdn2","static2","media2","bucket","storage","s3","blob",
    "us","eu","asia","ap","eu-west","us-east","us-west","eu-central","asia-east","sg","jp","au","ca","uk",
    "node1","node2","node3","node4","server1","server2","server3","host1","host2","web1","web2","app1","app2",
    "lb1","lb2","edge1","edge2","region-us","region-eu",
    "billing","pay","payment","payments","invoice","invoices","crm","erp","cms","wordpress","wp","wp-admin",
    "phpmyadmin","pma","sql","adminer","phppgadmin","redis-commander","rabbitmq-management","mq",
    "kibana-dev","elasticsearch-head","prometheus-ui","grafana-dev","alertmanager","blackbox",
    "sonar","sonarqube","nexus","repo","maven","docker-registry","registry","harbor",
    "jenkins-ci","ci-jenkins","build-jenkins","pipeline","ansible","puppet","chef",
    "zabbix","nagios","prom","loki","tempo","mimir","jaeger","tracing","opentelemetry",
    "legacy-app","old-app","archive","beta-app","internal-tool","tools","utils","debug","test-api",
    "sandbox-api","demo-app","poc-app","staging-app","preprod-app","uat-app","qa-app",
    "www2","www3","secure2","login2","portal2","admin2","api3","dev-api","prod-api"
]

def extract_base_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def is_tunnel_safe(ip, page_info):
    if not is_cloudflare_ip(ip):
        return False, "Direct exposure - not proxied! 🚨"
    
    if page_info["status"] == 200:
        if page_info.get("bypassed_403"):
            return True, "403 bypassed with real browser UA → SAFE TO TUNNEL! ⚡"
        return True, "200 OK + Proxied → SAFE TO TUNNEL ✅"
    
    if page_info["limited"]:
        return False, f"Cloudflare block: {page_info['reason']}"
    
    if page_info["status"] in [403, 401, 404, 502, 503, 429] or page_info["status"] is None:
        if test_raw_get_root(ip, is_https=True):
            return True, "Blocked but raw HTTPS GET / works → SAFE VIA TUNNEL! ⚡"
        if test_raw_get_root(ip, is_https=False):
            return True, "Blocked but raw HTTP GET / works → SAFE VIA TUNNEL! ⚡"
        ws_ok, proto = test_websocket_exact(ip)
        if ws_ok:
            return True, f"Blocked but {proto} WebSocket works → SAFE! ⚡"
        return False, "All bypass attempts failed → NOT SAFE"
    
    return False, f"HTTP {page_info['status']} → NOT SAFE"

print_lock = threading.Lock()

def analyze_host(host, potential_origin_ips):
    with print_lock:
        print(f"\n{'='*30} ANALYZING: {host.upper()} {'='*30}")
    
    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  ❌ No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  🌐 IP → {ip} | ☁️ {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"\033[92m{status_text} (OK!)\033[0m"
        if page.get("bypassed_403"):
            status_text += " \033[93m(via UA bypass)\033[0m"
    
    server = page.get("server")
    if not server and not page["limited"] and page["status"] in [200, 301, 302, 403]:
        with print_lock:
            print("  🔍 Server header missing → Probing raw connection...")
        server = fingerprint_server(ip)

    server_display = server or "Not detected"
    if "nginx" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (nginx)"
    elif "apache" in server_display.lower():
        server_display = f"\033[93m{server_display}\033[0m (Apache)"
    elif "iis" in server_display.lower() or "microsoft" in server_display.lower():
        server_display = f"\033[95m{server_display}\033[0m (Microsoft IIS)"
    elif "litespeed" in server_display.lower():
        server_display = f"\033[92m{server_display}\033[0m (LiteSpeed)"
    elif "openresty" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (OpenResty)"

    with print_lock:
        print(f"  📡 Status → {status_text}")
        print(f"  📑 Title  → {page['title']}")
        print(f"  🖥️  Web Server → {server_display}")
        print(f"  🚫 CF Block → {'YES' if page['limited'] else 'NO ✅'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  🔓 Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "\033[92m" if safe else "\033[91m"
    symbol = "✅ YES - SAFE TO TUNNEL!" if safe else "❌ NO"
    with print_lock:
        print(f"  🛡️  Tunnel Safe? → {color}{symbol}\033[0m")
        print(f"      └─ {reason}")

# ==================== FLASK + TELEBOT SETUP ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

output_buffer = StringIO()

class PrintRedirector:
    def write(self, text):
        output_buffer.write(text)
    def flush(self):
        pass

def run_scan(chat_id, targets):
    global output_buffer
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = PrintRedirector()

    all_origin_leaks = set()
    mx_check = False
    deep_brute = True       # Deep subdomain brute enabled

    for target in targets:
        print("\n" + "█"*100)
        print(f"🎯 TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'✅ YES' if safe else '❌ NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS and mx_check:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        if deep_brute:
            print("\n💥 Starting deep subdomain brute-force...")
            found = []
            def check(sub):
                full = f"{sub}.{base}"
                if full == target: return
                ip = resolve_host(full)
                if ip:
                    found.append(full)
                    tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                    print(f"    ✓ {full} → {ip}{tag}")
                    if not is_cloudflare_ip(ip):
                        local_leaks.add(ip)
                        all_origin_leaks.add(ip)
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(check, SUBDOMAIN_WORDLIST)
            hosts_to_check.extend(found)

        print("\n" + "─"*100)
        print("DETAILED ANALYSIS")
        print("─"*100)
        for h in hosts_to_check:
            analyze_host(h, all_origin_leaks)

        if local_leaks:
            print(f"\n🚨 LEAKS FOR {target}:")
            for ip in sorted(local_leaks):
                print(f"   → {ip}")

    print("\n" + "█"*100)
    prielse:
    PROXIES = None
    print("Direct mode (no proxy)")

def build_opener():
    if PROXIES:
        proxy_handler = urllib.request.ProxyHandler(PROXIES)
        opener = urllib.request.build_opener(proxy_handler)
        return opener
    return urllib.request

opener = build_opener()

# Random delay for stealth
def random_delay(min_sec=1.5, max_sec=4.5):
    time.sleep(random.uniform(min_sec, max_sec))

# ==================== AUTO-UPDATE CLOUDFLARE IP RANGES ====================
cf_networks = []

def update_cf_ranges():
    global cf_networks
    ranges = []
    try:
        resp = opener.urlopen("https://www.cloudflare.com/ips-v4", timeout=20)
        ranges.extend(resp.read().decode().strip().splitlines())
        resp = opener.urlopen("https://www.cloudflare.com/ips-v6", timeout=20)
        ranges.extend(resp.read().decode().strip().splitlines())
        cf_networks = [ipaddress.ip_network(net.strip()) for net in ranges if net.strip()]
        print(f"Cloudflare ranges updated automatically ({len(cf_networks)} ranges)")
    except Exception:
        print("Failed to update CF ranges - using fallback")
        fallback = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
            "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:8100::/32",
            "2405:b500::/32", "2a06:98c0::/29", "2c0f:f248::/32"
        ]
        cf_networks = [ipaddress.ip_network(net) for net in fallback]

update_cf_ranges()

def is_cloudflare_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in cf_networks)
    except:
        return False

# ==================== USER AGENTS & AUTO BYPASS HEADERS ====================
BYPASS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

AUTO_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "CF-Connecting-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
    "X-Cluster-Client-IP": "127.0.0.1",
    "Forwarded": "for=127.0.0.1",
    "X-ProxyUser-Ip": "127.0.0.1",
    "Client-IP": "127.0.0.1",
    "X-Cache-Key": "debug123",
    "Bypass-Tunnel": "origin-direct",
    "Origin-Bypass": "true"
}

# ==================== CORE FUNCTIONS ====================
def detect_web_server_from_headers(headers):
    server = headers.get('Server', '').strip()
    if server: return server
    powered = headers.get('X-Powered-By', '')
    if powered: return powered
    via = headers.get('Via', '')
    if via: return f"Proxy/Via: {via}"
    return None

def raw_server_banner(ip, port=443, use_ssl=True):
    random_delay()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(12)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 100 * 1024: break
        s.close()

        if not response: return None
        header_part = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
        headers = {}
        lines = header_part.splitlines()
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        return detect_web_server_from_headers(headers)
    except:
        return None

def fingerprint_server(ip):
    banner = raw_server_banner(ip, 443, True)
    if banner: return banner
    banner = raw_server_banner(ip, 80, False)
    if banner: return banner
    return "Unknown / Header Stripped"

def fetch_page(host):
    random_delay()
    status_code = None
    title = "No response"
    headers = {}
    is_rate_limited = False
    rate_limit_reason = ""
    bypassed_403 = False
    detected_server = None
    timeout = 18 if USE_TOR else 12

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ["https", "http"]:
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"})
            with opener.urlopen(req, timeout=timeout, context=ctx) as resp:
                status_code = resp.code
                headers = dict(resp.headers)
                detected_server = detect_web_server_from_headers(headers)
                data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                if m: title = m.group(1).strip()[:150]
                break
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(getattr(e, 'headers', {}))
            detected_server = detect_web_server_from_headers(headers)
            title = "Access Denied / Blocked"
        except:
            continue

    if status_code in [403, 401, 429, 503]:
        random.shuffle(BYPASS_USER_AGENTS)
        for ua in BYPASS_USER_AGENTS[:10]:
            random_delay()
            for scheme in ["https", "http"]:
                try:
                    extra_headers = {
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive"
                    }
                    req = urllib.request.Request(f"{scheme}://{host}", headers=extra_headers)
                    with opener.urlopen(req, timeout=timeout, context=ctx) as resp:
                        if resp.code == 200:
                            status_code = 200
                            headers = dict(resp.headers)
                            detected_server = detect_web_server_from_headers(headers)
                            data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                            m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                            if m: title = m.group(1).strip()[:150]
                            bypassed_403 = True
                            break
                except:
                    continue
            if bypassed_403: break

    if any(k in title.lower() for k in ["attention required", "checking your browser", "captcha", "ray id", "just a moment"]):
        is_rate_limited = True
        rate_limit_reason = "Cloudflare Challenge"

    return {
        "status": status_code,
        "title": title,
        "headers": headers,
        "limited": is_rate_limited,
        "reason": rate_limit_reason,
        "bypassed_403": bypassed_403,
        "server": detected_server
    }

def test_raw_get_root(ip, is_https=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, 443))
        else:
            s.connect((ip, 80))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
        s.close()
        if response:
            head = response.split(b"\r\n\r\n")[0].decode(errors='ignore')
            if "200" in head.splitlines()[0] or "301" in head.splitlines()[0] or "302" in head.splitlines()[0]:
                return True
        return False
    except:
        return False

def test_websocket_exact(ip):
    for scheme in ["wss", "ws"]:
        url = f"{scheme}://{ip}/"
        try:
            ws = websocket.WebSocket()
            ws.settimeout(10)
            ws.connect(url, custom_header=[("Host", ip), ("Connection", "Upgrade"), ("Upgrade", "websocket")])
            ws.close()
            return True, scheme.upper()
        except:
            continue
    return False, None

def scan_ports(ip):
    ports = [21, 22, 80, 443, 8080, 8443, 2222, 3389, 3306, 5432, 25, 587]
    open_ports = []
    def try_port(p):
        try:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(try_port, ports)
    return sorted(open_ports)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_mx(domain):
    if not HAS_DNS: return []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        leaks = []
        for rdata in answers:
            mail = str(rdata.exchange).rstrip('.')
            ip = resolve_host(mail)
            if ip:
                leaks.append((mail, ip))
        return leaks
    except:
        return []

SUBDOMAIN_WORDLIST = [
    "direct","direct-connect","origin","mail","webmail","smtp","pop","pop3","imap","ftp","cpanel","whm","webdisk",
    "admin","portal","dev","staging","test","beta","api","app","mobile","status","dashboard","login","secure",
    "vpn","remote","ssh","bastion","db","mysql","panel","server","node","backup","ns1","ns2","autoconfig",
    "autodiscover","mx","owa","exchange","intranet","git","jenkins","docker","k8s","monitor","grafana",
    "prometheus","kibana","elasticsearch","redis","rabbitmq","sentry","www","cdn","assets","static","media"
]

def extract_base_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def is_tunnel_safe(ip, page_info):
    if not is_cloudflare_ip(ip):
        return False, "Direct exposure - not proxied! 🚨"
    
    if page_info["status"] == 200:
        if page_info.get("bypassed_403"):
            return True, "403 bypassed with real browser UA → SAFE TO TUNNEL! ⚡"
        return True, "200 OK + Proxied → SAFE TO TUNNEL ✅"
    
    if page_info["limited"]:
        return False, f"Cloudflare block: {page_info['reason']}"
    
    if page_info["status"] in [403, 401, 404, 502, 503, 429] or page_info["status"] is None:
        if test_raw_get_root(ip, is_https=True):
            return True, "Blocked but raw HTTPS GET / works → SAFE VIA TUNNEL! ⚡"
        if test_raw_get_root(ip, is_https=False):
            return True, "Blocked but raw HTTP GET / works → SAFE VIA TUNNEL! ⚡"
        ws_ok, proto = test_websocket_exact(ip)
        if ws_ok:
            return True, f"Blocked but {proto} WebSocket works → SAFE! ⚡"
        return False, "All bypass attempts failed → NOT SAFE"
    
    return False, f"HTTP {page_info['status']} → NOT SAFE"

# ==================== CUSTOM HEADER PAYLOAD TEST ====================
def test_custom_headers_on_origin(ip, custom_headers, port=443, use_ssl=True):
    if not custom_headers:
        return None, None

    random_delay()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(12)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))

        header_lines = [f"{k}: {v}" for k, v in custom_headers.items()]
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n" +
            "\r\n".join(header_lines) + "\r\n\r\n"
        )
        s.sendall(request.encode())

        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 200 * 1024: break
        s.close()

        if not response:
            return None, "No response"

        full_resp = response.decode('utf-8', errors='ignore')
        headers_part = full_resp.split('\r\n\r\n')[0]
        body = full_resp.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in full_resp else ""

        reflected_headers = []
        lower_headers = {k.lower(): v for k, v in re.findall(r'^(\S+): (.+)$', headers_part, re.M)}
        for k, v in custom_headers.items():
            if lower_headers.get(k.lower()) == v:
                reflected_headers.append(f"{k}: {v}")

        leaked_in_body = [f"{k}: {v}" for k, v in custom_headers.items() if v in body]

        result = []
        if reflected_headers:
            result.append(f"REFLECTED in response headers: {', '.join(reflected_headers)}")
        if leaked_in_body:
            result.append(f"LEAKED in response body: {', '.join(leaked_in_body)}")

        status_line = headers_part.splitlines()[0] if headers_part.splitlines() else ""

        if result:
            return "\n".join(result), status_line
        else:
            return "No leak/reflection detected", status_line

    except Exception:
        return None, "Connection failed"

# ==================== ANALYZE HOST (WITH AUTO PAYLOAD ON 200 OK) ====================
print_lock = threading.Lock()

def analyze_host(host, potential_origin_ips):
    with print_lock:
        print(f"\n{'='*30} ANALYZING: {host.upper()} {'='*30}")
    
    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  IP → {ip} | {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"{status_text} (OK!)"
        if page.get("bypassed_403"):
            status_text += " (via UA bypass)"

    server = page.get("server")
    if not server and page["status"] in [200, 301, 302, 403]:
        server = fingerprint_server(ip)

    server_display = server or "Not detected"

    with print_lock:
        print(f"  Status → {status_text}")
        print(f"  Title  → {page['title']}")
        print(f"  Web Server → {server_display}")
        print(f"  CF Block → {'YES' if page['limited'] else 'NO'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "" if safe else ""
    symbol = "YES - SAFE TO TUNNEL!" if safe else "NO"
    with print_lock:
        print(f"  Tunnel Safe? → {symbol}")
        print(f"      └─ {reason}")

    # AUTO BYPASS HEADER TEST ON DIRECT 200 OK
    if not is_cloudflare_ip(ip) and page['status'] == 200:
        with print_lock:
            print(f"\nDIRECT 200 OK → AUTO-TESTING BYPASS HEADERS")
            print(f"    Sending {len(AUTO_BYPASS_HEADERS)} headers...")
        triggered = False
        for port, ssl in [(443, True), (80, False)]:
            result, status = test_custom_headers_on_origin(ip, AUTO_BYPASS_HEADERS, port, ssl)
            if result and "No leak" not in result:
                proto = "HTTPS" if ssl else "HTTP"
                with print_lock:
                    print(f"   [{proto}:{port}] {status}")
                    print(f"   → {result}")
                    print(f"   DIRECT ORIGIN CONFIRMED VIA HEADER LEAK!")
                triggered = True
                break
        if not triggered:
            with print_lock:
                print("   → No header reflection/leak (still direct 200 OK)")

# ==================== SCAN LOGIC ====================
def run_scan(chat_id, targets):
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = output_buffer

    all_origin_leaks = set()

    for target in targets:
        print("\n" + "█"*100)
        print(f"TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'YES' if safe else 'NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        print("\nStarting deep subdomain brute-force...")
        found = []
        def check(sub):
            full = f"{sub}.{base}"
            if full == target: return
            ip = resolve_host(full)
            if ip:
                found.append(full)
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                print(f"    {full} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
        with ThreadPoolExecutor(max_workers=50) as ex:
            ex.map(chec
def is_cloudflare_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in cf_networks)
    except:
        return False

BYPASS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

def detect_web_server_from_headers(headers):
    server = headers.get('Server', '').strip()
    if server:
        return server
    powered = headers.get('X-Powered-By', '')
    if powered:
        return powered
    via = headers.get('Via', '')
    if via:
        return f"Proxy/Via: {via}"
    return None

def raw_server_banner(ip, port=443, use_ssl=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 100 * 1024: break
        s.close()

        if not response:
            return None

        header_part = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
        headers = {}
        lines = header_part.splitlines()
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        return detect_web_server_from_headers(headers)
    except:
        return None

def fingerprint_server(ip):
    banner = raw_server_banner(ip, 443, True)
    if banner:
        return banner
    banner = raw_server_banner(ip, 80, False)
    if banner:
        return banner
    return "Unknown / Header Stripped"

def fetch_page(host):
    status_code = None
    title = "No response"
    headers = {}
    is_rate_limited = False
    rate_limit_reason = ""
    bypassed_403 = False
    detected_server = None

    for scheme in ["https", "http"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"}
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                status_code = resp.code
                headers = dict(resp.headers)
                detected_server = detect_web_server_from_headers(headers)
                data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:150]
                break
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(getattr(e, 'headers', {}))
            detected_server = detect_web_server_from_headers(headers)
            title = "Access Denied / Blocked"
        except:
            continue

    if status_code in [403, 401, 429, 503]:
        random.shuffle(BYPASS_USER_AGENTS)
        for ua in BYPASS_USER_AGENTS[:10]:
            for scheme in ["https", "http"]:
                try:
                    extra_headers = {
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive"
                    }
                    req = urllib.request.Request(f"{scheme}://{host}", headers=extra_headers)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                        if resp.code == 200:
                            status_code = 200
                            headers = dict(resp.headers)
                            detected_server = detect_web_server_from_headers(headers)
                            data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                            m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                            if m:
                                title = m.group(1).strip()[:150]
                            bypassed_403 = True
                            break
                except:
                    continue
            if bypassed_403:
                break

    if any(k in title.lower() for k in ["attention required", "checking your browser", "captcha", "ray id"]):
        is_rate_limited = True
        rate_limit_reason = "Cloudflare Challenge"

    return {
        "status": status_code,
        "title": title,
        "headers": headers,
        "limited": is_rate_limited,
        "reason": rate_limit_reason,
        "bypassed_403": bypassed_403,
        "server": detected_server
    }

def test_raw_get_root(ip, is_https=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, 443))
        else:
            s.connect((ip, 80))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
        s.close()
        if response:
            head = response.split(b"\r\n\r\n")[0].decode(errors='ignore')
            if "200" in head.splitlines()[0] or "301" in head.splitlines()[0] or "302" in head.splitlines()[0]:
                return True
        return False
    except:
        return False

def test_websocket_exact(ip):
    for scheme in ["wss", "ws"]:
        url = f"{scheme}://{ip}/"
        try:
            ws = websocket.WebSocket()
            ws.settimeout(10)
            custom_headers = [
                ("Host", ip),
                ("Connection", "Keep-Alive"),
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket")
            ]
            ws.connect(url, custom_header=custom_headers)
            ws.close()
            return True, scheme.upper()
        except:
            continue
    return False, None

def scan_ports(ip):
    ports = [21, 22, 80, 443, 8080, 8443, 2222, 3389, 3306, 5432, 25, 587]
    open_ports = []
    def try_port(p):
        try:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(try_port, ports)
    return sorted(open_ports)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_mx(domain):
    if not HAS_DNS: return []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        leaks = []
        for rdata in answers:
            mail = str(rdata.exchange).rstrip('.')
            ip = resolve_host(mail)
            if ip:
                leaks.append((mail, ip))
        return leaks
    except:
        return []

SUBDOMAIN_WORDLIST = [
    "direct","direct-connect","origin","mail","webmail","smtp","pop","pop3","imap","ftp","cpanel","whm","webdisk",
    "admin","portal","dev","staging","test","beta","api","app","mobile","status","dashboard","login","secure",
    "vpn","remote","ssh","bastion","db","mysql","panel","server","node","backup","ns1","ns2","autoconfig",
    "autodiscover","mx","owa","exchange","intranet","git","jenkins","docker","k8s","monitor","grafana",
    "prometheus","kibana","elasticsearch","redis","rabbitmq","sentry","www","cdn","assets","static","media"
]

def extract_base_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def is_tunnel_safe(ip, page_info):
    if not is_cloudflare_ip(ip):
        return False, "Direct exposure - not proxied! 🚨"
    
    if page_info["status"] == 200:
        if page_info.get("bypassed_403"):
            return True, "403 bypassed with real browser UA → SAFE TO TUNNEL! ⚡"
        return True, "200 OK + Proxied → SAFE TO TUNNEL ✅"
    
    if page_info["limited"]:
        return False, f"Cloudflare block: {page_info['reason']}"
    
    if page_info["status"] in [403, 401, 404, 502, 503, 429] or page_info["status"] is None:
        if test_raw_get_root(ip, is_https=True):
            return True, "Blocked but raw HTTPS GET / works → SAFE VIA TUNNEL! ⚡"
        if test_raw_get_root(ip, is_https=False):
            return True, "Blocked but raw HTTP GET / works → SAFE VIA TUNNEL! ⚡"
        ws_ok, proto = test_websocket_exact(ip)
        if ws_ok:
            return True, f"Blocked but {proto} WebSocket works → SAFE! ⚡"
        return False, "All bypass attempts failed → NOT SAFE"
    
    return False, f"HTTP {page_info['status']} → NOT SAFE"

print_lock = threading.Lock()

def analyze_host(host, potential_origin_ips):
    with print_lock:
        print(f"\n{'='*30} ANALYZING: {host.upper()} {'='*30}")
    
    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  ❌ No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  🌐 IP → {ip} | ☁️ {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"\033[92m{status_text} (OK!)\033[0m"
        if page.get("bypassed_403"):
            status_text += " \033[93m(via UA bypass)\033[0m"
    
    server = page.get("server")
    if not server and not page["limited"] and page["status"] in [200, 301, 302, 403]:
        with print_lock:
            print("  🔍 Server header missing → Probing raw connection...")
        server = fingerprint_server(ip)

    server_display = server or "Not detected"
    if "nginx" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (nginx)"
    elif "apache" in server_display.lower():
        server_display = f"\033[93m{server_display}\033[0m (Apache)"
    elif "iis" in server_display.lower() or "microsoft" in server_display.lower():
        server_display = f"\033[95m{server_display}\033[0m (Microsoft IIS)"
    elif "litespeed" in server_display.lower():
        server_display = f"\033[92m{server_display}\033[0m (LiteSpeed)"
    elif "openresty" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (OpenResty)"

    with print_lock:
        print(f"  📡 Status → {status_text}")
        print(f"  📑 Title  → {page['title']}")
        print(f"  🖥️  Web Server → {server_display}")
        print(f"  🚫 CF Block → {'YES' if page['limited'] else 'NO ✅'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  🔓 Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "\033[92m" if safe else "\033[91m"
    symbol = "✅ YES - SAFE TO TUNNEL!" if safe else "❌ NO"
    with print_lock:
        print(f"  🛡️  Tunnel Safe? → {color}{symbol}\033[0m")
        print(f"      └─ {reason}")

# ==================== FLASK + TELEBOT SETUP ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

output_buffer = StringIO()

class PrintRedirector:
    def write(self, text):
        output_buffer.write(text)
    def flush(self):
        pass

def run_scan(chat_id, targets):
    global output_buffer
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = PrintRedirector()

    all_origin_leaks = set()
    mx_check = False        # You can change to True if you want MX checks too
    deep_brute = True       # <<< DEEP SUBDOMAIN BRUTE IS NOW ENABLED

    for target in targets:
        print("\n" + "█"*100)
        print(f"🎯 TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'✅ YES' if safe else '❌ NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS and mx_check:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        if deep_brute:
            print("\n💥 Starting deep subdomain brute-force...")
            found = []
            def check(sub):
                full = f"{sub}.{base}"
                if full == target: return
                ip = resolve_host(full)
                if ip:
                    found.append(full)
                    tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                    print(f"    ✓ {full} → {ip}{tag}")
                    if not is_cloudflare_ip(ip):
                        local_leaks.add(ip)
                        all_origin_leaks.add(ip)
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(check, SUBDOMAIN_WORDLIST)
            hosts_to_check.extend(found)

        print("\n" + "─"*100)
        print("DETAILED ANALYSIS")
        print("─"*100)
        for h in hosts_to_check:
            analyze_host(h, all_origin_leaks)

        if local_leaks:
            print(f"\n🚨 LEAKS FOR {target}:")
            for ip in sorted(local_leaks):
                print(f"   → {ip}")

    print("\n" + "█"*100)
    print("GLOBAL SUMMARY")
    print("█"*100)
    if all_origin_leaks:
        print("🚨 DIRECT ORIGIN LEAKS FOUND:")
        for ip in sorted(all_origin_leaks):
            print(f"   → {ip}")
    else:
        print("✅ NO LEAKS - FULLY PROTECTED!")

    print("\n🎉 Scan complete! 🚀\n")

    sys.stdout = old_stdout
    results = output_buffer.getvalue()

    bot.send_message(chat_id, "🔍 Scan in progress... (deep brute enabled — may take 2–10 minutes)")
    for i in range(0, len(results), 3900):
        bot.send_message(chat_id, f"<pre>{results[i:i+3900]}</pre>", parse_mode='HTML')
    bot.send_message(chat_id, "✅ Scan finished!")

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "🔍 <b>Cloudflare Leak & Tunnel Safety Scanner</b>\n\n"
                          "Send a domain or IP to scan.\n"
                          "Or upload a .txt file with targets (one per line).\n\n"
                          "Deep subdomain brute is now <b>ENABLED</b> (scans take longer but find more leaks).\n"
                          "Bot running 24/7 on Render 🚀", parse_mode='HTML')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "Please send a .txt file only.")
        return
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    targets = [line.decode('utf-8').strip() for line in downloaded.splitlines() 
               if line.strip() and not line.startswith(b'#')]
    if targets:
        bot.reply_to(message, f"📂 Loaded {len(targets)} targets. Starting deep scan...")
        run_scan(message.chat.id, targets)
    else:
        bot.reply_to(message, "No valid targets found in the file.")

@bot.message_handler(func=lambda m: True)
def handle_text(message):
    target = message.text.strip()
    if target:
        bot.reply_to(message, "🔍 Starting deep scan on target...")
        run_scan(message.chat.id, [target])

@app.route('/' + TOKEN, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_json(force=True)
        update = types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    abort(403)

@app.route('/')
def index():
    return "Cloudflare Scanner Bot is alive! 🚀"

if __name__ == '__main__':
    bot.remove_webhook()
    bot.polling()
else:
    bot.remove_webhook()
    time.sleep(1)
    service_url = f"https://{os.getenv('RENDER_SERVICE_NAME')}.onrender.com"
    webhook_url = f"{service_url}/{TOKEN}"
    bot.set_webhook(url=webhook_url)
    print(f"Webhook set to: {webhook_url}")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 100 * 1024: break
        s.close()

        if not response:
            return None

        header_part = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
        headers = {}
        lines = header_part.splitlines()
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        return detect_web_server_from_headers(headers)
    except:
        return None

def fingerprint_server(ip):
    banner = raw_server_banner(ip, 443, True)
    if banner:
        return banner
    banner = raw_server_banner(ip, 80, False)
    if banner:
        return banner
    return "Unknown / Header Stripped"

def fetch_page(host):
    status_code = None
    title = "No response"
    headers = {}
    is_rate_limited = False
    rate_limit_reason = ""
    bypassed_403 = False
    detected_server = None

    for scheme in ["https", "http"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"}
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                status_code = resp.code
                headers = dict(resp.headers)
                detected_server = detect_web_server_from_headers(headers)
                data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:150]
                break
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(getattr(e, 'headers', {}))
            detected_server = detect_web_server_from_headers(headers)
            title = "Access Denied / Blocked"
        except:
            continue

    if status_code in [403, 401, 429, 503]:
        random.shuffle(BYPASS_USER_AGENTS)
        for ua in BYPASS_USER_AGENTS[:10]:
            for scheme in ["https", "http"]:
                try:
                    extra_headers = {
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive"
                    }
                    req = urllib.request.Request(f"{scheme}://{host}", headers=extra_headers)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                        if resp.code == 200:
                            status_code = 200
                            headers = dict(resp.headers)
                            detected_server = detect_web_server_from_headers(headers)
                            data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                            m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                            if m:
                                title = m.group(1).strip()[:150]
                            bypassed_403 = True
                            break
                except:
                    continue
            if bypassed_403:
                break

    if any(k in title.lower() for k in ["attention required", "checking your browser", "captcha", "ray id"]):
        is_rate_limited = True
        rate_limit_reason = "Cloudflare Challenge"

    return {
        "status": status_code,
        "title": title,
        "headers": headers,
        "limited": is_rate_limited,
        "reason": rate_limit_reason,
        "bypassed_403": bypassed_403,
        "server": detected_server
    }

def test_raw_get_root(ip, is_https=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, 443))
        else:
            s.connect((ip, 80))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            responsRenderhunk
        s.close()
        if response:
            head = response.split(b"\r\n\r\n")[0].decode(errors='ignore')
            if "200" in head.splitlines()[0] or "301" in head.splitlines()[0] or "302" in head.splitlines()[0]:
                return True
        return False
    except:
        return False

def test_websocket_exact(ip):
    for scheme in ["wss", "ws"]:
        url = f"{scheme}://{ip}/"
        try:
            ws = websocket.WebSocket()
            ws.settimeout(10)
            custom_headers = [
                ("Host", ip),
                ("Connection", "Keep-Alive"),
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket")
            ]
            ws.connect(url, custom_header=custom_headers)
            ws.close()
            return True, scheme.upper()
        except:
            continue
    return False, None

def scan_ports(ip):
    ports = [21, 22, 80, 443, 8080, 8443, 2222, 3389, 3306, 5432, 25, 587]
    open_ports = []
    def try_port(p):
        try:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(try_port, ports)
    return sorted(open_ports)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_mx(domain):
    if not HAS_DNS: return []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        leaks = []
        for rdata in answers:
            mail = str(rdata.exchange).rstrip('.')
            ip = resolve_host(mail)
            if ip:
                leaks.append((mail, ip))
        return leaks
    except:
        return []

SUBDOMAIN_WORDLIST = [
    "direct","direct-connect","origin","mail","webmail","smtp","pop","pop3","imap","ftp","cpanel","whm","webdisk",
    "admin","portal","dev","staging","test","beta","api","app","mobile","status","dashboard","login","secure",
    "vpn","remote","ssh","bastion","db","mysql","panel","server","node","backup","ns1","ns2","autoconfig",
    "autodiscover","mx","owa","exchange","intranet","git","jenkins","docker","k8s","monitor","grafana",
    "prometheus","kibana","elasticsearch","redis","rabbitmq","sentry","www","cdn","assets","static","media"
]

def extract_base_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def is_tunnel_safe(ip, page_info):
    if not is_cloudflare_ip(ip):
        return False, "Direct exposure - not proxied! 🚨"
    
    if page_info["status"] == 200:
        if page_info.get("bypassed_403"):
            return True, "403 bypassed with real browser UA → SAFE TO TUNNEL! ⚡"
        return True, "200 OK + Proxied → SAFE TO TUNNEL ✅"
    
    if page_info["limited"]:
        return False, f"Cloudflare block: {page_info['reason']}"
    
    if page_info["status"] in [403, 401, 404, 502, 503, 429] or page_info["status"] is None:
        if test_raw_get_root(ip, is_https=True):
            return True, "Blocked but raw HTTPS GET / works → SAFE VIA TUNNEL! ⚡"
        if test_raw_get_root(ip, is_https=False):
            return True, "Blocked but raw HTTP GET / works → SAFE VIA TUNNEL! ⚡"
        ws_ok, proto = test_websocket_exact(ip)
        if ws_ok:
            return True, f"Blocked but {proto} WebSocket works → SAFE! ⚡"
        return False, "All bypass attempts failed → NOT SAFE"
    
    return False, f"HTTP {page_info['status']} → NOT SAFE"

print_lock = threading.Lock()

def analyze_host(host, potential_origin_ips):
    with print_lock:
        print(f"\n{'='*30} ANALYZING: {host.upper()} {'='*30}")
    
    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  ❌ No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  🌐 IP → {ip} | ☁️ {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"\033[92m{status_text} (OK!)\033[0m"
        if page.get("bypassed_403"):
            status_text += " \033[93m(via UA bypass)\033[0m"
    
    server = page.get("server")
    if not server and not page["limited"] and page["status"] in [200, 301, 302, 403]:
        with print_lock:
            print("  🔍 Server header missing → Probing raw connection...")
        server = fingerprint_server(ip)

    server_display = server or "Not detected"
    if "nginx" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (nginx)"
    elif "apache" in server_display.lower():
        server_display = f"\033[93m{server_display}\033[0m (Apache)"
    elif "iis" in server_display.lower() or "microsoft" in server_display.lower():
        server_display = f"\033[95m{server_display}\033[0m (Microsoft IIS)"
    elif "litespeed" in server_display.lower():
        server_display = f"\033[92m{server_display}\033[0m (LiteSpeed)"
    elif "openresty" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (OpenResty)"

    with print_lock:
        print(f"  📡 Status → {status_text}")
        print(f"  📑 Title  → {page['title']}")
        print(f"  🖥️  Web Server → {server_display}")
        print(f"  🚫 CF Block → {'YES' if page['limited'] else 'NO ✅'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  🔓 Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "\033[92m" if safe else "\033[91m"
    symbol = "✅ YES - SAFE TO TUNNEL!" if safe else "❌ NO"
    with print_lock:
        print(f"  🛡️  Tunnel Safe? → {color}{symbol}\033[0m")
        print(f"      └─ {reason}")

# ==================== FLASK + TELEBOT SETUP ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

output_buffer = StringIO()

class PrintRedirector:
    def write(self, text):
        output_buffer.write(text)
    def flush(self):
        pass

def run_scan(chat_id, targets):
    global output_buffer
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = PrintRedirector()

    all_origin_leaks = set()
    mx_check = False        # You can change to True if you want MX checks too
    deep_brute = True       # <<< DEEP SUBDOMAIN BRUTE IS NOW ENABLED

    for target in targets:
        print("\n" + "█"*100)
        print(f"🎯 TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'✅ YES' if safe else '❌ NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS and mx_check:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        if deep_brute:
            print("\n💥 Starting deep subdomain brute-force...")
            found = []
            def check(sub):
                full = f"{sub}.{base}"
                if full == target: return
                ip = resolve_host(full)
                if ip:
                    found.append(full)
                    tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                    print(f"    ✓ {full} → {ip}{tag}")
                    if not is_cloudflare_ip(ip):
                        local_leaks.add(ip)
                        all_origin_leaks.add(ip)
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(check, SUBDOMAIN_WORDLIST)
            hosts_to_check.extend(found)

        print("\n" + "─"*100)
        print("DETAILED ANALYSIS")
        print("─"*100)
        for h in hosts_to_check:
            analyze_host(h, all_origin_leaks)

        if local_leaks:
            print(f"\n🚨 LEAKS FOR {target}:")
            for ip in sorted(local_leaks):
                print(f"   → {ip}")

    print("\n" + "█"*100)
    print("GLOBAL SUMMARY")
    print("█"*100)
    if all_origin_leaks:
        print("🚨 DIRECT ORIGIN LEAKS FOUND:")
        for ip in sorted(all_origin_leaks):
            print(f"   → {ip}")
    else:
        print("✅ NO LEAKS - FULLY PROTECTED!")

    print("\n🎉 Scan complete! 🚀\n")

    sys.stdout = old_stdout
    results = output_buffer.getvalue()

    bot.send_message(chat_id, "🔍 Scan in progress... (deep brute enabled — may take 2–10 minutes)")
    for i in range(0, len(results), 3900):
        bot.send_message(chat_id, f"<pre>{results[i:i+3900]}</pre>", parse_mode='HTML')
    bot.send_message(chat_id, "✅ Scan finished!")

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "🔍 <b>Cloudflare Leak & Tunnel Safety Scanner</b>\n\n"
                          "Send a domain or IP to scan.\n"
                          "Or upload a .txt file with targets (one per line).\n\n"
                          "Deep subdomain brute is now <b>ENABLED</b> (scans take longer but find more leaks).\n"
                          "Bot running 24/7 🚀", parse_mode='HTML')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "Please send a .txt file only.")
        return
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    targets = [line.decode('utf-8').strip() for line in downloaded.splitlines() 
               if line.strip() and not line.startswith(b'#')]
    if targets:
        bot.reply_to(message, f"📂 Loaded {len(targets)} targets. Starting deep scan...")
        run_scan(message.chat.id, targets)
    else:
        bot.reply_to(message, "No valid targets found in the file.")

@bot.message_handler(func=lambda m: True)
def handle_text(message):
    target = message.text.strip()
    if target:
        bot.reply_to(message, "🔍 Starting deep scan on target...")
        run_scan(message.chat.id, [target])

@app.route('/' + TOKEN, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_json(force=True)
        update = types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    abort(403)

@app.route('/')
def index():
    return "Cloudflare Scanner Bot is alive! 🚀"

if __name__ == '__main__':
    bot.remove_webhook()
    bot.polling()
else:
    bot.remove_webhook()
    time.sleep(1)
    service_url = f"https://{os.getenv('RENDER_SERVICE_NAME')}.onrender.com"
    webhook_url = f"{service_url}/{TOKEN}"
    bot.set_webhook(url=webhook_url)
    print(f"Webhook set to: {webhook_url}")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
# ==================== YOUR FUNCTIONS (unchanged) ====================
# (All your original functions: is_cloudflare_ip, fetch_page, analyze_host, etc.)
# Paste them exactly as before — I'm skipping them here for brevity, but keep them all!

# ... [all the functions from previous code: is_cloudflare_ip to analyze_host] ...

# ==================== PRIVATE ACCESS CONTROL ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

# <<< PUT YOUR AND FRIENDS' USER IDs HERE >>>
ALLOWED_USERS = []  # Example: [123456789, 987654321, 555555555]

def is_allowed(user_id):
    return user_id in ALLOWED_USERS

# ==================== SCAN LOGIC (same as before) ====================
# run_scan function unchanged — deep_brute = True

def run_scan(chat_id, targets):
    # ... (same as previous version)

# ==================== MESSAGE HANDLERS WITH ACCESS CHECK ====================
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    if not is_allowed(message.from_user.id):
        bot.reply_to(message, "❌ Access denied. This bot is private.")
        return
    bot.reply_to(message, "🔍 <b>Cloudflare Leak & Tunnel Safety Scanner</b>\n\n"
                          "Send a domain or IP to scan.\n"
                          "Or upload a .txt file with targets (one per line).\n\n"
                          "Deep subdomain brute is now <b>ENABLED</b> (scans take longer but find more leaks).", parse_mode='HTML')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if not is_allowed(message.from_user.id):
        bot.reply_to(message, "❌ Access denied.")
        return
    # ... (same document handling)

@bot.message_handler(func=lambda m: True)
def handle_text(message):
    if not is_allowed(message.from_user.id):
        bot.reply_to(message, "❌ Access denied.")
        return
    # ... (same text handling)

# ==================== WEBHOOK ====================
@app.route('/' + TOKEN, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_json(force=True)
        update = types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    abort(403)

@app.route('/')
def index():
    return "Private CF Scanner Bot"

if __name__ == '__main__':
    bot.remove_webhook()
    bot.polling()
else:
    bot.remove_webhook()
    time.sleep(1)
    service_url = f"https://{os.getenv('RENDER_SERVICE_NAME')}.onrender.com"
    webhook_url = f"{service_url}/{TOKEN}"
    bot.set_webhook(url=webhook_url)
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  ❌ No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  🌐 IP → {ip} | ☁️ {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"\033[92m{status_text} (OK!)\033[0m"
        if page.get("bypassed_403"):
            status_text += " \033[93m(via UA bypass)\033[0m"
    
    server = page.get("server")
    if not server and not page["limited"] and page["status"] in [200, 301, 302, 403]:
        with print_lock:
            print("  🔍 Server header missing → Probing raw connection...")
        server = fingerprint_server(ip)

    server_display = server or "Not detected"
    if "nginx" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (nginx)"
    elif "apache" in server_display.lower():
        server_display = f"\033[93m{server_display}\033[0m (Apache)"
    elif "iis" in server_display.lower() or "microsoft" in server_display.lower():
        server_display = f"\033[95m{server_display}\033[0m (Microsoft IIS)"
    elif "litespeed" in server_display.lower():
        server_display = f"\033[92m{server_display}\033[0m (LiteSpeed)"
    elif "openresty" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (OpenResty)"

    with print_lock:
        print(f"  📡 Status → {status_text}")
        print(f"  📑 Title  → {page['title']}")
        print(f"  🖥️  Web Server → {server_display}")
        print(f"  🚫 CF Block → {'YES' if page['limited'] else 'NO ✅'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  🔓 Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "\033[92m" if safe else "\033[91m"
    symbol = "✅ YES - SAFE TO TUNNEL!" if safe else "❌ NO"
    with print_lock:
        print(f"  🛡️  Tunnel Safe? → {color}{symbol}\033[0m")
        print(f"      └─ {reason}")

# ==================== FLASK + TELEBOT SETUP ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

output_buffer = StringIO()

class PrintRedirector:
    def write(self, text):
        output_buffer.write(text)
    def flush(self):
        pass

def run_scan(chat_id, targets):
    global output_buffer
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = PrintRedirector()

    all_origin_leaks = set()
    mx_check = False
    deep_brute = True       # Deep subdomain brute enabled

    for target in targets:
        print("\n" + "█"*100)
        print(f"🎯 TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'✅ YES' if safe else '❌ NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS and mx_check:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        if deep_brute:
            print("\n💥 Starting deep subdomain brute-force...")
            found = []
            def check(sub):
                full = f"{sub}.{base}"
                if full == target: return
                ip = resolve_host(full)
                if ip:
                    found.append(full)
                    tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                    print(f"    ✓ {full} → {ip}{tag}")
                    if not is_cloudflare_ip(ip):
                        local_leaks.add(ip)
                        all_origin_leaks.add(ip)
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(check, SUBDOMAIN_WORDLIST)
            hosts_to_check.extend(found)

        print("\n" + "─"*100)
        print("DETAILED ANALYSIS")
        print("─"*100)
        for h in hosts_to_check:
            analyze_host(h, all_origin_leaks)

        if local_leaks:
            print(f"\n🚨 LEAKS FOR {target}:")
            for ip in sorted(local_leaks):
                print(f"   → {ip}")

    print("\n" + "█"*100)
    print("GLOBAL SUMMARY")
    print("█"*100)
    if all_origin_leaks:
        print("🚨 DIRECT ORIGIN LEAKS FOUND:")
        for ip in sorted(all_origin_leaks):
            print(f"   → {ip}")
    else:
        print("✅ NO LEAKS - FULLY PROTECTED!")

    print("\n🎉 Scan complete! 🚀\n")

    sys.stdout = old_stdout
    results = output_buffer.getvalue()

    bot.send_message(chat_id, "🔍 Scan in progress... (deep brute enabled — may take 2–10 minutes)")
    for i in range(0, len(results), 3900):
        bot.send_message(chat_id, f"<pre>{results[i:i+3900]}</pre>", parse_mode='HTML')
    bot.send_message(chat_id, "✅ Scan finished!")

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "🔍 <b>Cloudflare Leak & Tunnel Safety Scanner</b>\n\n"
                          "Send a domain or IP to scan.\n"
                          "Or upload a .txt file with targets (one per line).\n\n"
                          "Deep subdomain brute is now <b>ENABLED</b> (scans take longer but find more leaks).", parse_mode='HTML')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "Please send a .txt file only.")
        return
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    targets = [line.decode('utf-8').strip() for line in downloaded.splitlines() 
               if line.strip() and not line.startswith(b'#')]
    if targets:
        bot.reply_to(message, f"📂 Loaded {len(targets)} targets. Starting deep scan...")
        run_scan(message.chat.id, targets)
    else:
        bot.reply_to(message, "No valid targets found in the file.")

@bot.message_handler(func=lambda m: True)
def handle_text(message):
    target = message.text.strip()
    if target:
        bot.reply_to(message, "🔍 Starting deep scan on target...")
        run_scan(message.chat.id, [target])

@app.route('/' + TOKEN, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_json(force=True)
        update = types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    abort(403)

@app.route('/')
def index():
    return "Cloudflare Scanner Bot is alive! 🚀"

if __name__ == '__main__':
    bot.remove_webhook()
    bot.polling()
else:
    bot.remove_webhook()
    time.sleep(1)
    service_url = f"https://{os.getenv('RENDER_SERVICE_NAME')}.onrender.com"
    webhook_url = f"{service_url}/{TOKEN}"
    bot.set_webhook(url=webhook_url)
    print(f"Webhook set to: {webhook_url}")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
def is_cloudflare_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in cf_networks)
    except:
        return False

BYPASS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

def detect_web_server_from_headers(headers):
    server = headers.get('Server', '').strip()
    if server:
        return server
    powered = headers.get('X-Powered-By', '')
    if powered:
        return powered
    via = headers.get('Via', '')
    if via:
        return f"Proxy/Via: {via}"
    return None

def raw_server_banner(ip, port=443, use_ssl=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 100 * 1024: break
        s.close()

        if not response:
            return None

        header_part = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
        headers = {}
        lines = header_part.splitlines()
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        return detect_web_server_from_headers(headers)
    except:
        return None

def fingerprint_server(ip):
    banner = raw_server_banner(ip, 443, True)
    if banner:
        return banner
    banner = raw_server_banner(ip, 80, False)
    if banner:
        return banner
    return "Unknown / Header Stripped"

def fetch_page(host):
    status_code = None
    title = "No response"
    headers = {}
    is_rate_limited = False
    rate_limit_reason = ""
    bypassed_403 = False
    detected_server = None

    for scheme in ["https", "http"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"}
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                status_code = resp.code
                headers = dict(resp.headers)
                detected_server = detect_web_server_from_headers(headers)
                data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:150]
                break
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(getattr(e, 'headers', {}))
            detected_server = detect_web_server_from_headers(headers)
            title = "Access Denied / Blocked"
        except:
            continue

    if status_code in [403, 401, 429, 503]:
        random.shuffle(BYPASS_USER_AGENTS)
        for ua in BYPASS_USER_AGENTS[:10]:
            for scheme in ["https", "http"]:
                try:
                    extra_headers = {
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive"
                    }
                    req = urllib.request.Request(f"{scheme}://{host}", headers=extra_headers)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                        if resp.code == 200:
                            status_code = 200
                            headers = dict(resp.headers)
                            detected_server = detect_web_server_from_headers(headers)
                            data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                            m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                            if m:
                                title = m.group(1).strip()[:150]
                            bypassed_403 = True
                            break
                except:
                    continue
            if bypassed_403:
                break

    if any(k in title.lower() for k in ["attention required", "checking your browser", "captcha", "ray id"]):
        is_rate_limited = True
        rate_limit_reason = "Cloudflare Challenge"

    return {
        "status": status_code,
        "title": title,
        "headers": headers,
        "limited": is_rate_limited,
        "reason": rate_limit_reason,
        "bypassed_403": bypassed_403,
        "server": detected_server
    }

def test_raw_get_root(ip, is_https=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, 443))
        else:
            s.connect((ip, 80))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
        s.close()
        if response:
            head = response.split(b"\r\n\r\n")[0].decode(errors='ignore')
            if "200" in head.splitlines()[0] or "301" in head.splitlines()[0] or "302" in head.splitlines()[0]:
                return True
        return False
    except:
        return False

def test_websocket_exact(ip):
    for scheme in ["wss", "ws"]:
        url = f"{scheme}://{ip}/"
        try:
            ws = websocket.WebSocket()
            ws.settimeout(10)
            custom_headers = [
                ("Host", ip),
                ("Connection", "Keep-Alive"),
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket")
            ]
            ws.connect(url, custom_header=custom_headers)
            ws.close()
            return True, scheme.upper()
        except:
            continue
    return False, None

def scan_ports(ip):
    ports = [21, 22, 80, 443, 8080, 8443, 2222, 3389, 3306, 5432, 25, 587]
    open_ports = []
    def try_port(p):
        try:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(try_port, ports)
    return sorted(open_ports)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_mx(domain):
    if not HAS_DNS: return []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        leaks = []
        for rdata in answers:
            mail = str(rdata.exchange).rstrip('.')
            ip = resolve_host(mail)
            if ip:
                leaks.append((mail, ip))
        return leaks
    except:
        return []

SUBDOMAIN_WORDLIST = [
    "direct","direct-connect","origin","mail","webmail","smtp","pop","pop3","imap","ftp","cpanel","whm","webdisk",
    "admin","portal","dev","staging","test","beta","api","app","mobile","status","dashboard","login","secure",
    "vpn","remote","ssh","bastion","db","mysql","panel","server","node","backup","ns1","ns2","autoconfig",
    "autodiscover","mx","owa","exchange","intranet","git","jenkins","docker","k8s","monitor","grafana",
    "prometheus","kibana","elasticsearch","redis","rabbitmq","sentry","www","cdn","assets","static","media"
]

def extract_base_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def is_tunnel_safe(ip, page_info):
    if not is_cloudflare_ip(ip):
        return False, "Direct exposure - not proxied! 🚨"
    
    if page_info["status"] == 200:
        if page_info.get("bypassed_403"):
            return True, "403 bypassed with real browser UA → SAFE TO TUNNEL! ⚡"
        return True, "200 OK + Proxied → SAFE TO TUNNEL ✅"
    
    if page_info["limited"]:
        return False, f"Cloudflare block: {page_info['reason']}"
    
    if page_info["status"] in [403, 401, 404, 502, 503, 429] or page_info["status"] is None:
        if test_raw_get_root(ip, is_https=True):
            return True, "Blocked but raw HTTPS GET / works → SAFE VIA TUNNEL! ⚡"
        if test_raw_get_root(ip, is_https=False):
            return True, "Blocked but raw HTTP GET / works → SAFE VIA TUNNEL! ⚡"
        ws_ok, proto = test_websocket_exact(ip)
        if ws_ok:
            return True, f"Blocked but {proto} WebSocket works → SAFE! ⚡"
        return False, "All bypass attempts failed → NOT SAFE"
    
    return False, f"HTTP {page_info['status']} → NOT SAFE"

print_lock = threading.Lock()

def analyze_host(host, potential_origin_ips):
    with print_lock:
        print(f"\n{'='*30} ANALYZING: {host.upper()} {'='*30}")
    
    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  ❌ No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  🌐 IP → {ip} | ☁️ {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"\033[92m{status_text} (OK!)\033[0m"
        if page.get("bypassed_403"):
            status_text += " \033[93m(via UA bypass)\033[0m"
    
    server = page.get("server")
    if not server and not page["limited"] and page["status"] in [200, 301, 302, 403]:
        with print_lock:
            print("  🔍 Server header missing → Probing raw connection...")
        server = fingerprint_server(ip)

    server_display = server or "Not detected"
    if "nginx" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (nginx)"
    elif "apache" in server_display.lower():
        server_display = f"\033[93m{server_display}\033[0m (Apache)"
    elif "iis" in server_display.lower() or "microsoft" in server_display.lower():
        server_display = f"\033[95m{server_display}\033[0m (Microsoft IIS)"
    elif "litespeed" in server_display.lower():
        server_display = f"\033[92m{server_display}\033[0m (LiteSpeed)"
    elif "openresty" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (OpenResty)"

    with print_lock:
        print(f"  📡 Status → {status_text}")
        print(f"  📑 Title  → {page['title']}")
        print(f"  🖥️  Web Server → {server_display}")
        print(f"  🚫 CF Block → {'YES' if page['limited'] else 'NO ✅'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  🔓 Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "\033[92m" if safe else "\033[91m"
    symbol = "✅ YES - SAFE TO TUNNEL!" if safe else "❌ NO"
    with print_lock:
        print(f"  🛡️  Tunnel Safe? → {color}{symbol}\033[0m")
        print(f"      └─ {reason}")

# ==================== FLASK + TELEBOT SETUP ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(TOKEN)

output_buffer = StringIO()

class PrintRedirector:
    def write(self, text):
        output_buffer.write(text)
    def flush(self):
        pass

def run_scan(chat_id, targets):
    global output_buffer
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = PrintRedirector()

    all_origin_leaks = set()
    mx_check = False        # You can change to True if you want MX checks too
    deep_brute = True       # <<< DEEP SUBDOMAIN BRUTE IS NOW ENABLED

    for target in targets:
        print("\n" + "█"*100)
        print(f"🎯 TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'✅ YES' if safe else '❌ NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS and mx_check:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        if deep_brute:
            print("\n💥 Starting deep subdomain brute-force...")
            found = []
            def check(sub):
                full = f"{sub}.{base}"
                if full == target: return
                ip = resolve_host(full)
                if ip:
                    found.append(full)
                    tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                    print(f"    ✓ {full} → {ip}{tag}")
                    if not is_cloudflare_ip(ip):
                        local_leaks.add(ip)
                        all_origin_leaks.add(ip)
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(check, SUBDOMAIN_WORDLIST)
            hosts_to_check.extend(found)

        print("\n" + "─"*100)
        print("DETAILED ANALYSIS")
        print("─"*100)
        for h in hosts_to_check:
            analyze_host(h, all_origin_leaks)

        if local_leaks:
            print(f"\n🚨 LEAKS FOR {target}:")
            for ip in sorted(local_leaks):
                print(f"   → {ip}")

    print("\n" + "█"*100)
    print("GLOBAL SUMMARY")
    print("█"*100)
    if all_origin_leaks:
        print("🚨 DIRECT ORIGIN LEAKS FOUND:")
        for ip in sorted(all_origin_leaks):
            print(f"   → {ip}")
    else:
        print("✅ NO LEAKS - FULLY PROTECTED!")

    print("\n🎉 Scan complete! 🚀\n")

    sys.stdout = old_stdout
    results = output_buffer.getvalue()

    bot.send_message(chat_id, "🔍 Scan in progress... (deep brute enabled — may take 2–10 minutes)")
    for i in range(0, len(results), 3900):
        bot.send_message(chat_id, f"<pre>{results[i:i+3900]}</pre>", parse_mode='HTML')
    bot.send_message(chat_id, "✅ Scan finished!")

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "🔍 <b>Cloudflare Leak & Tunnel Safety Scanner</b>\n\n"
                          "Send a domain or IP to scan.\n"
                          "Or upload a .txt file with targets (one per line).\n\n"
                          "Deep subdomain brute is now <b>ENABLED</b> (scans take longer but find more leaks).\n"
                          "Bot running 🚀", parse_mode='HTML')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "Please send a .txt file only.")
        return
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    targets = [line.decode('utf-8').strip() for line in downloaded.splitlines() 
               if line.strip() and not line.startswith(b'#')]
    if targets:
        bot.reply_to(message, f"📂 Loaded {len(targets)} targets. Starting deep scan...")
        run_scan(message.chat.id, targets)
    else:
        bot.reply_to(message, "No valid targets found in the file.")

@bot.message_handler(func=lambda m: True)
def handle_text(message):
    target = message.text.strip()
    if target:
        bot.reply_to(message, "🔍 Starting deep scan on target...")
        run_scan(message.chat.id, [target])

@app.route('/' + TOKEN, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_json(force=True)
        update = types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    abort(403)

@app.route('/')
def index():
    return "Cloudflare Scanner Bot is alive! 🚀"

if __name__ == '__main__':
    bot.remove_webhook()
    bot.polling()
else:
    bot.remove_webhook()
    time.sleep(1)
    service_url = f"https://{os.getenv('RENDER_SERVICE_NAME')}.onrender.com"
    webhook_url = f"{service_url}/{TOKEN}"
    bot.set_webhook(url=webhook_url)
    print(f"Webhook set to: {webhook_url}")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
def is_cloudflare_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in cf_networks)
    except:
        return False

BYPASS_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

def detect_web_server_from_headers(headers):
    server = headers.get('Server', '').strip()
    if server:
        return server
    powered = headers.get('X-Powered-By', '')
    if powered:
        return powered
    via = headers.get('Via', '')
    if via:
        return f"Proxy/Via: {via}"
    return None

def raw_server_banner(ip, port=443, use_ssl=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            data = s.recv(8192)
            if not data: break
            response += data
            if len(response) > 100 * 1024: break
        s.close()

        if not response:
            return None

        header_part = response.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
        headers = {}
        lines = header_part.splitlines()
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        return detect_web_server_from_headers(headers)
    except:
        return None

def fingerprint_server(ip):
    banner = raw_server_banner(ip, 443, True)
    if banner:
        return banner
    banner = raw_server_banner(ip, 80, False)
    if banner:
        return banner
    return "Unknown / Header Stripped"

def fetch_page(host):
    status_code = None
    title = "No response"
    headers = {}
    is_rate_limited = False
    rate_limit_reason = ""
    bypassed_403 = False
    detected_server = None

    for scheme in ["https", "http"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10; Mobile)"}
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                status_code = resp.code
                headers = dict(resp.headers)
                detected_server = detect_web_server_from_headers(headers)
                data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:150]
                break
        except urllib.error.HTTPError as e:
            status_code = e.code
            headers = dict(getattr(e, 'headers', {}))
            detected_server = detect_web_server_from_headers(headers)
            title = "Access Denied / Blocked"
        except:
            continue

    if status_code in [403, 401, 429, 503]:
        random.shuffle(BYPASS_USER_AGENTS)
        for ua in BYPASS_USER_AGENTS[:10]:
            for scheme in ["https", "http"]:
                try:
                    extra_headers = {
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive"
                    }
                    req = urllib.request.Request(f"{scheme}://{host}", headers=extra_headers)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                        if resp.code == 200:
                            status_code = 200
                            headers = dict(resp.headers)
                            detected_server = detect_web_server_from_headers(headers)
                            data = resp.read(150 * 1024).decode('utf-8', errors='ignore')
                            m = re.search(r'<title>(.*?)</title>', data, re.I | re.S)
                            if m:
                                title = m.group(1).strip()[:150]
                            bypassed_403 = True
                            break
                except:
                    continue
            if bypassed_403:
                break

    if any(k in title.lower() for k in ["attention required", "checking your browser", "captcha", "ray id"]):
        is_rate_limited = True
        rate_limit_reason = "Cloudflare Challenge"

    return {
        "status": status_code,
        "title": title,
        "headers": headers,
        "limited": is_rate_limited,
        "reason": rate_limit_reason,
        "bypassed_403": bypassed_403,
        "server": detected_server
    }

def test_raw_get_root(ip, is_https=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=ip)
            s.connect((ip, 443))
        else:
            s.connect((ip, 80))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
        s.close()
        if response:
            head = response.split(b"\r\n\r\n")[0].decode(errors='ignore')
            if "200" in head.splitlines()[0] or "301" in head.splitlines()[0] or "302" in head.splitlines()[0]:
                return True
        return False
    except:
        return False

def test_websocket_exact(ip):
    for scheme in ["wss", "ws"]:
        url = f"{scheme}://{ip}/"
        try:
            ws = websocket.WebSocket()
            ws.settimeout(10)
            custom_headers = [
                ("Host", ip),
                ("Connection", "Keep-Alive"),
                ("Connection", "Upgrade"),
                ("Upgrade", "websocket")
            ]
            ws.connect(url, custom_header=custom_headers)
            ws.close()
            return True, scheme.upper()
        except:
            continue
    return False, None

def scan_ports(ip):
    ports = [21, 22, 80, 443, 8080, 8443, 2222, 3389, 3306, 5432, 25, 587]
    open_ports = []
    def try_port(p):
        try:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(try_port, ports)
    return sorted(open_ports)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def check_mx(domain):
    if not HAS_DNS: return []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        leaks = []
        for rdata in answers:
            mail = str(rdata.exchange).rstrip('.')
            ip = resolve_host(mail)
            if ip:
                leaks.append((mail, ip))
        return leaks
    except:
        return []

SUBDOMAIN_WORDLIST = [
    "direct","direct-connect","origin","mail","webmail","smtp","pop","pop3","imap","ftp","cpanel","whm","webdisk",
    "admin","portal","dev","staging","test","beta","api","app","mobile","status","dashboard","login","secure",
    "vpn","remote","ssh","bastion","db","mysql","panel","server","node","backup","ns1","ns2","autoconfig",
    "autodiscover","mx","owa","exchange","intranet","git","jenkins","docker","k8s","monitor","grafana",
    "prometheus","kibana","elasticsearch","redis","rabbitmq","sentry","www","cdn","assets","static","media"
]

def extract_base_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def is_tunnel_safe(ip, page_info):
    if not is_cloudflare_ip(ip):
        return False, "Direct exposure - not proxied! 🚨"
    
    if page_info["status"] == 200:
        if page_info.get("bypassed_403"):
            return True, "403 bypassed with real browser UA → SAFE TO TUNNEL! ⚡"
        return True, "200 OK + Proxied → SAFE TO TUNNEL ✅"
    
    if page_info["limited"]:
        return False, f"Cloudflare block: {page_info['reason']}"
    
    if page_info["status"] in [403, 401, 404, 502, 503, 429] or page_info["status"] is None:
        if test_raw_get_root(ip, is_https=True):
            return True, "Blocked but raw HTTPS GET / works → SAFE VIA TUNNEL! ⚡"
        if test_raw_get_root(ip, is_https=False):
            return True, "Blocked but raw HTTP GET / works → SAFE VIA TUNNEL! ⚡"
        ws_ok, proto = test_websocket_exact(ip)
        if ws_ok:
            return True, f"Blocked but {proto} WebSocket works → SAFE! ⚡"
        return False, "All bypass attempts failed → NOT SAFE"
    
    return False, f"HTTP {page_info['status']} → NOT SAFE"

print_lock = threading.Lock()

def analyze_host(host, potential_origin_ips):
    with print_lock:
        print(f"\n{'='*30} ANALYZING: {host.upper()} {'='*30}")
    
    ip = resolve_host(host)
    if not ip:
        with print_lock:
            print("  ❌ No DNS resolution")
        return
    
    cf_status = "PROXIED" if is_cloudflare_ip(ip) else "DIRECT (LEAK! 🚨)"
    with print_lock:
        print(f"  🌐 IP → {ip} | ☁️ {cf_status}")
    
    if not is_cloudflare_ip(ip):
        potential_origin_ips.add(ip)

    page = fetch_page(host)
    status_text = f"{page['status'] or 'No response'}"
    if page['status'] == 200:
        status_text = f"\033[92m{status_text} (OK!)\033[0m"
        if page.get("bypassed_403"):
            status_text += " \033[93m(via UA bypass)\033[0m"
    
    server = page.get("server")
    if not server and not page["limited"] and page["status"] in [200, 301, 302, 403]:
        with print_lock:
            print("  🔍 Server header missing → Probing raw connection...")
        server = fingerprint_server(ip)

    server_display = server or "Not detected"
    if "nginx" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (nginx)"
    elif "apache" in server_display.lower():
        server_display = f"\033[93m{server_display}\033[0m (Apache)"
    elif "iis" in server_display.lower() or "microsoft" in server_display.lower():
        server_display = f"\033[95m{server_display}\033[0m (Microsoft IIS)"
    elif "litespeed" in server_display.lower():
        server_display = f"\033[92m{server_display}\033[0m (LiteSpeed)"
    elif "openresty" in server_display.lower():
        server_display = f"\033[96m{server_display}\033[0m (OpenResty)"

    with print_lock:
        print(f"  📡 Status → {status_text}")
        print(f"  📑 Title  → {page['title']}")
        print(f"  🖥️  Web Server → {server_display}")
        print(f"  🚫 CF Block → {'YES' if page['limited'] else 'NO ✅'}")

    ports = scan_ports(ip)
    if ports:
        with print_lock:
            print(f"  🔓 Open Ports → {ports}")

    safe, reason = is_tunnel_safe(ip, page)
    color = "\033[92m" if safe else "\033[91m"
    symbol = "✅ YES - SAFE TO TUNNEL!" if safe else "❌ NO"
    with print_lock:
        print(f"  🛡️  Tunnel Safe? → {color}{symbol}\033[0m")
        print(f"      └─ {reason}")

# ==================== FLASK + TELEBOT SETUP ====================
app = Flask(__name__)

TOKEN = os.getenv('BOT_TOKEN')  # ← Set this in Render Environment Variables
bot = telebot.TeleBot(TOKEN)

output_buffer = StringIO()

class PrintRedirector:
    def write(self, text):
        output_buffer.write(text)
    def flush(self):
        pass

def run_scan(chat_id, targets):
    global output_buffer
    output_buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = PrintRedirector()

    all_origin_leaks = set()
    mx_check = False      # Set True if you want MX checks (may be slower)
    deep_brute = False    # Set True if you want subdomain brute (very slow on bot)

    for target in targets:
        print("\n" + "█"*100)
        print(f"🎯 TARGET: {target.upper()}")
        print("█"*100)
        
        try:
            ipaddress.ip_address(target)
            print(f"  Direct IP → Cloudflare? {'YES' if is_cloudflare_ip(target) else 'NO → LEAK! 🚨'}")
            ports = scan_ports(target)
            print(f"  Open ports: {ports or 'None'}")
            if not is_cloudflare_ip(target):
                all_origin_leaks.add(target)
            page = fetch_page(target)
            safe, reason = is_tunnel_safe(target, page)
            print(f"  Tunnel Safe? {'✅ YES' if safe else '❌ NO'} → {reason}")
            continue
        except:
            pass
        
        base = extract_base_domain(target)
        hosts_to_check = [target]
        local_leaks = set()

        if HAS_DNS and mx_check:
            for mail, ip in check_mx(base):
                tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else ""
                print(f"    → {mail} → {ip}{tag}")
                if not is_cloudflare_ip(ip):
                    local_leaks.add(ip)
                    all_origin_leaks.add(ip)
                hosts_to_check.append(mail)

        if deep_brute:
            found = []
            def check(sub):
                full = f"{sub}.{base}"
                if full == target: return
                ip = resolve_host(full)
                if ip:
                    found.append(full)
                    tag = " (LEAK! 🚨)" if not is_cloudflare_ip(ip) else " (proxied)"
                    print(f"    ✓ {full} → {ip}{tag}")
                    if not is_cloudflare_ip(ip):
                        local_leaks.add(ip)
                        all_origin_leaks.add(ip)
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(check, SUBDOMAIN_WORDLIST)
            hosts_to_check.extend(found)

        print("\n" + "─"*100)
        print("DETAILED ANALYSIS")
        print("─"*100)
        for h in hosts_to_check:
            analyze_host(h, all_origin_leaks)

        if local_leaks:
            print(f"\n🚨 LEAKS FOR {target}:")
            for ip in sorted(local_leaks):
                print(f"   → {ip}")

    print("\n" + "█"*100)
    print("GLOBAL SUMMARY")
    print("█"*100)
    if all_origin_leaks:
        print("🚨 DIRECT ORIGIN LEAKS FOUND:")
        for ip in sorted(all_origin_leaks):
            print(f"   → {ip}")
    else:
        print("✅ NO LEAKS - FULLY PROTECTED!")

    print("\n🎉 Scan complete! 🚀\n")

    sys.stdout = old_stdout
    results = output_buffer.getvalue()

    bot.send_message(chat_id, "🔍 Scan in progress... (may take 30-90 seconds)")
    for i in range(0, len(results), 3900):
        bot.send_message(chat_id, f"<pre>{results[i:i+3900]}</pre>", parse_mode='HTML')
    bot.send_message(chat_id, "✅ Scan finished!")

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "🔍 <b>Cloudflare Leak & Tunnel Safety Scanner</b>\n\n"
                          "Send a domain or IP to scan.\n"
                          "Or upload a .txt file with targets (one per line).\n\n"
                          "Deep subdomain brute and MX checks are off by default for speed.\n"
                          "Bot running 24/7 on Render 🚀", parse_mode='HTML')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "Please send a .txt file only.")
        return
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    targets = [line.decode('utf-8').strip() for line in downloaded.splitlines() 
               if line.strip() and not line.startswith(b'#')]
    if targets:
        bot.reply_to(message, f"📂 Loaded {len(targets)} targets. Starting scan...")
        run_scan(message.chat.id, targets)
    else:
        bot.reply_to(message, "No valid targets found in the file.")

@bot.message_handler(func=lambda m: True)
def handle_text(message):
    target = message.text.strip()
    if target:
        bot.reply_to(message, "🔍 Scanning target...")
        run_scan(message.chat.id, [target])

# Webhook routes
@app.route('/' + TOKEN, methods=['POST'])
def webhook():
    if request.headers.get('content-type') == 'application/json':
        json_string = request.get_json(force=True)
        update = types.Update.de_json(json_string)
        bot.process_new_updates([update])
        return ''
    abort(403)

@app.route('/')
def index():
    return "Cloudflare Scanner Bot is alive! 🚀"

# Run
if __name__ == '__main__':
    # For local testing only
    bot.remove_webhook()
    bot.polling()
else:
    # Production on Render
    bot.remove_webhook()
    time.sleep(1)
    service_url = f"https://{os.getenv('RENDER_SERVICE_NAME')}.onrender.com"
    webhook_url = f"{service_url}/{TOKEN}"
    bot.set_webhook(url=webhook_url)
    print(f"Webhook set to: {webhook_url}")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
