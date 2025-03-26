import argparse
import requests
import socket
import ssl
import dns.resolver
import dns.query
import dns.zone
import ipaddress
import subprocess
import whois
import shutil
import os
from datetime import datetime, timezone
from termcolor import colored

def get_color(value, field):
    """Determine 'green', 'yellow', 'red', or None based on field logic."""
    value_lower = str(value).lower()

    if field in ["Up", "SPF", "DKIM", "DMARC", "HTTP to HTTPS Redirect",
                 "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"]:
        if value_lower == "yes":
            return "green"
        elif value_lower == "no":
            return "red"
    
    elif field == "Blacklist Status":
        if value_lower == "clean":
            return "green"
        elif value_lower == "listed":
            return "red"

    elif field == "SSL Config Status":
        if value_lower == "ok":
            return "green"
        elif "weak" in value_lower:
            return "yellow"
        else:
            return "red"

    elif field == "Zone Transfer Status":
        if "vulnerable" in value_lower:
            return "red"
        elif value_lower == "secure":
            return "green"

    elif field in ["SSL Days Left", "Domain Expiry (days)"]:
        try:
            num = int(value)
            if num > 30:
                return "green"
            elif 7 <= num <= 30:
                return "yellow"
            elif num < 7:
                return "red"
        except:
            return "red"

    return None

def colorize(value, field):
    """Colorize for terminal display."""
    color = get_color(value, field)
    return colored(str(value), color) if color else str(value)

def html_colorize(value, field):
    """Colorize for HTML output."""
    raw = str(value)
    color = get_color(value, field)
    return f'<span class="{color}">{raw}</span>' if color else raw

def load_domains_from_csv(csv_path):
    domains = []

    if not os.path.exists(csv_path):
        print(f"[WARN] CSV file not found at {csv_path}.")
        user_input = input("Would you like to add a domain to start with? (y/n): ").strip().lower()
        if user_input == "y":
            new_domain = input("Enter a domain to add: ").strip()
            if new_domain:
                with open(csv_path, "w", newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=["domain"])
                    writer.writeheader()
                    writer.writerow({"domain": new_domain})
                    domains.append(new_domain)
                    print(f"[INFO] Created {csv_path} with domain: {new_domain}")
        else:
            print("[INFO] Exiting. No CSV loaded and no domain entered.")
    else:
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                domain = row.get("domain")
                if domain:
                    domains.append(domain.strip())

    return domains


def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

def check_http_status(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def get_ssl_expiry(domain):
    try:
        print(f"[DEBUG] Attempting SSL check for: {domain}")
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert['notAfter']
                expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                print(f"[DEBUG] SSL cert for {domain} expires in {days_left} days")
                return days_left
    except ssl.SSLError:
        return "SSL handshake failed"
    except socket.timeout:
        return "Connection timeout"
    except socket.gaierror:
        return "DNS resolution failed"
    except Exception as e:
        return f"Error: {e}"

def check_mail_records(domain):
    results = {"SPF": "No", "DKIM": "No", "DMARC": "No"}
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for rdata in spf_records:
            for txt_string in rdata.strings:
                if b"v=spf1" in txt_string:
                    results["SPF"] = "Yes"

        dkim_domain = f"default._domainkey.{domain}"
        try:
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in dkim_records:
                for txt_string in rdata.strings:
                    if b"v=DKIM1" in txt_string:
                        results["DKIM"] = "Yes"
        except:
            pass

        dmarc_domain = f"_dmarc.{domain}"
        try:
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in dmarc_records:
                for txt_string in rdata.strings:
                    if b"v=DMARC1" in txt_string:
                        results["DMARC"] = "Yes"
        except:
            pass

    except Exception as e:
        print(f"DNS lookup failed: {e}")

    return results

def check_security_headers(domain):
    headers_to_check = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy"
    ]
    results = {header: "No" for header in headers_to_check}

    try:
        response = requests.get(f"https://{domain}", timeout=5)
        for header in headers_to_check:
            if header in response.headers:
                results[header] = "Yes"
    except Exception as e:
        print(f"Failed to fetch headers for {domain}: {e}")

    return results

def check_dnsbl(domain):
    dnsbls = ["zen.spamhaus.org", "bl.spamcop.net"]
    try:
        ip = socket.gethostbyname(domain)
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for dnsbl in dnsbls:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                socket.gethostbyname(query)
                return "Listed"
            except socket.gaierror:
                continue
        return "Clean"
    except Exception as e:
        return f"Error: {e}"

def get_domain_whois_info(domain):
    try:
        w = whois.whois(domain)
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if expiry_date and expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        days_left = (expiry_date - datetime.now(timezone.utc)).days if expiry_date else "Unknown"

        registrar = w.registrar or w.org or "Unknown"

        return days_left, registrar
    except Exception as e:
        return f"Error: {e}", "Unknown"

def check_http_to_https(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        return "Yes" if response.url.startswith("https://") else "No"
    except Exception as e:
        return f"Error: {e}"

def check_tech_stack(domain):
    stack_info = {
        "Server": "Unknown",
        "X-Powered-By": "Unknown",
        "Framework": "Unknown",
        "CMS Detected": "None"
    }

    cms_signatures = {
        "WordPress": ["wp-content", "wp-includes", "generator\" content=\"WordPress"],
        "Drupal": ["sites/all/", "misc/drupal.js", "generator\" content=\"Drupal"],
        "Joomla": ["content=\"Joomla!", "media/system/js/"],
        "Magento": ["skin/frontend", "Mage.Cookies", "Magento"],
        "Shopify": ["cdn.shopify.com", "Shopify.theme", "X-ShopId"],
        "Wix": ["static.parastorage.com", "Wix", "X-Wix-Request-Id"],
        "Squarespace": ["static.squarespace.com", "sqs-layout-view", "Squarespace"],
        "React": ["react-dom", "React.createElement"],
        "Vue": ["Vue.config", "__vue__"],
        "Angular": ["ng-version", "ng-app"]
    }

    try:
        response = requests.get(f"https://{domain}", timeout=5)
        html = response.text.lower()

        if "Server" in response.headers:
            stack_info["Server"] = response.headers["Server"]
        if "X-Powered-By" in response.headers:
            stack_info["X-Powered-By"] = response.headers["X-Powered-By"]

        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if sig.lower() in html:
                    stack_info["CMS Detected"] = cms
                    break
            if stack_info["CMS Detected"] != "None":
                break

    except Exception as e:
        stack_info["Error"] = str(e)

    return stack_info

def check_dns_provider(domain):
    result = {
        "A Record IP": "Unknown",
        "AAAA Record IP": "None",
        "NS Records": [],
        "DNS Provider Guess": "Unknown"
    }
    try:
        ip = socket.gethostbyname(domain)
        result["A Record IP"] = ip
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            result["AAAA Record IP"] = str(aaaa_records[0])
        except:
            pass
        known_ranges = {
            "Cloudflare": ["104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22"],
            "Google": ["216.239.32.0/19", "172.217.0.0/16"],
            "AWS": ["13.32.0.0/15", "13.224.0.0/14", "205.251.192.0/19"],
            "Microsoft Azure": ["20.36.0.0/14", "40.74.0.0/15"]
        }
        ip_obj = ipaddress.ip_address(ip)
        for provider, cidrs in known_ranges.items():
            for cidr in cidrs:
                if ip_obj in ipaddress.ip_network(cidr):
                    result["DNS Provider Guess"] = provider
                    break
            if result["DNS Provider Guess"] != "Unknown":
                break
    except Exception as e:
        print(f"[DEBUG] A record failed: {e}")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        result["NS Records"] = [str(r.target).rstrip('.') for r in ns_records]
    except Exception as e:
        print(f"[DEBUG] NS record lookup failed: {e}")
    return result

def check_ssl_config(domain):
    try:
        result = subprocess.run(
            ["nmap", "--script", "ssl-cert,ssl-enum-ciphers", "-p", "443", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20
        )
        if result.returncode != 0:
            return "Nmap error"
        output = result.stdout
        if "SSLv2" in output or "weak" in output or "error" in output.lower():
            return "Weak SSL config"
        return "OK"
    except FileNotFoundError:
        return "nmap not installed"
    except subprocess.TimeoutExpired:
        return "Timed out"
    except Exception as e:
        return f"Error: {e}"

def enumerate_subdomains(domain):
    subfinder_path = shutil.which("subfinder") or os.path.expanduser("~/go/bin/subfinder")
    all_subdomains = set()

    if subfinder_path:
        try:
            print(f"[INFO] Running subfinder on {domain}...")
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                subs = result.stdout.strip().splitlines()
                all_subdomains.update(subs)
            else:
                print(f"[WARN] subfinder failed: {result.stderr.strip()}")
        except Exception as e:
            print(f"[ERROR] subfinder exception: {e}")
    else:
        print("[WARN] subfinder not found.")

    return sorted(all_subdomains)

def check_zone_transfer(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns = str(ns.target).rstrip(".")
            try:
                axfr = dns.query.xfr(ns, domain, lifetime=10)
                zone = dns.zone.from_xfr(axfr)
                if zone:
                    return f"VULNERABLE (Zone transfer succeeded on {ns})"
            except Exception:
                continue
        return "Secure"
    except Exception as e:
        return f"Error: {e}"

def evaluate_domain(domain):
    is_up = check_http_status(domain)
    ssl_days_left = get_ssl_expiry(domain) if is_up else None
    domain_expiry_days, registrar = get_domain_whois_info(domain)
    mail_results = check_mail_records(domain)
    header_results = check_security_headers(domain)
    tech_results = check_tech_stack(domain)
    dns_results = check_dns_provider(domain)
    subdomains = enumerate_subdomains(domain)
    zone_transfer = check_zone_transfer(domain)

    return {
        "Domain": domain,
        "Up": "Yes" if is_up else "No",
        "SSL Days Left": ssl_days_left if ssl_days_left is not None else "-",
        "Domain Expiry (days)": domain_expiry_days,
        "Registrar / Org": registrar,
        "SPF": mail_results["SPF"],
        "DKIM": mail_results["DKIM"],
        "DMARC": mail_results["DMARC"],
        "Strict-Transport-Security": header_results["Strict-Transport-Security"],
        "X-Frame-Options": header_results["X-Frame-Options"],
        "X-XSS-Protection": header_results["X-XSS-Protection"],
        "Content-Security-Policy": header_results["Content-Security-Policy"],
        "Blacklist Status": check_dnsbl(domain),
        "HTTP to HTTPS Redirect": check_http_to_https(domain),
        "Server": tech_results["Server"],
        "X-Powered-By": tech_results["X-Powered-By"],
        "Framework": tech_results["Framework"],
        "CMS Detected": tech_results["CMS Detected"],
        "A Record IP": dns_results["A Record IP"],
        "NS Records": ", ".join(dns_results["NS Records"]),
        "DNS Provider Guess": dns_results["DNS Provider Guess"],
        "AAAA Record IP": dns_results["AAAA Record IP"],
        "Reverse DNS": reverse_dns_lookup(dns_results["A Record IP"]),
        "SSL Config Status": check_ssl_config(domain),
        "Zone Transfer Status": zone_transfer,
        "Subdomains": subdomains
    }

def print_results(results):
    for r in results:
        print("=" * 50)
        for key, value in r.items():
            if key == "Subdomains":
                print("Subdomains:")
                for sub in value:
                    print(f"  - {sub}")
            else:
                print(f"{key}: {colorize(value, key)}")
        print("=" * 50)
        print()

from datetime import datetime

def save_html_report(results, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
    filename = os.path.join(output_dir, f"report-{timestamp}.html")

    html_parts = [f"""
    <html><head><style>
    body {{ font-family: Arial; background: #f9f9f9; padding: 20px; }}
    h2 {{ border-bottom: 1px solid #ccc; }}
    table {{ border-collapse: collapse; margin-bottom: 30px; }}
    td {{ padding: 6px 10px; vertical-align: top; }}
    .green {{ color: green; font-weight: bold; }}
    .yellow {{ color: orange; font-weight: bold; }}
    .red {{ color: red; font-weight: bold; }}
    </style></head><body>
    <h1>Domain Health Report - {datetime.now().strftime("%Y-%m-%d %H:%M")}</h1>
    """]

    for r in results:
        domain = r.get("Domain", "Unknown Domain")
        html_parts.append(f"<h2>{domain}</h2><table>")
        for key, value in r.items():
            if key == "Subdomains":
                subs = "<br>".join(value) if value else "None"
                html_parts.append(f"<tr><td><strong>{key}</strong></td><td>{subs}</td></tr>")
            else:
                html_parts.append(f"<tr><td><strong>{key}</strong></td><td>{html_colorize(value, key)}</td></tr>")
        html_parts.append("</table>")

    html_parts.append("</body></html>")

    with open(filename, "w") as f:
        f.write("\n".join(html_parts))

    print(f"📄 HTML report saved to: {filename}")

def main():
            csv_path = "domains.csv"
            domains = []
        
            parser = argparse.ArgumentParser(description="Domain Health Checker")
            parser.add_argument("--from-csv", action="store_true", help="Scan all domains from the saved CSV file")
            parser.add_argument("--add", metavar="DOMAIN", help="Add a domain manually (bypasses prompt)")
            args = parser.parse_args()
        
            if args.from_csv:
                if not os.path.exists(csv_path):
                    print(f"[WARN] CSV file not found at {csv_path}.")
                    return
                with open(csv_path, "r") as f:
                    domains = [line.strip() for line in f if line.strip() and not line.lower().startswith("domain")]
            elif args.add:
                domains = [args.add]
                if not os.path.exists(csv_path):
                    with open(csv_path, "w") as f:
                        f.write("domain\n")
                with open(csv_path, "r") as f:
                    existing = {line.strip().lower() for line in f if line.strip()}
                if args.add.lower() not in existing:
                    with open(csv_path, "a") as f:
                        f.write(f"{args.add}\n")
                    print(f"[INFO] Domain {args.add} saved to {csv_path}.")
                else:
                    print(f"[INFO] Domain {args.add} already exists in {csv_path}.")
            else:
                if not os.path.exists(csv_path):
                    print(f"[WARN] CSV file not found at {csv_path}.")
                    user_input = input("Would you like to add a domain to start with? (y/n or type domain): ").strip()
                    if user_input.lower() in ["y", "yes"]:
                        domain = input("Enter the domain to scan: ").strip()
                        if domain:
                            domains.append(domain)
                            with open(csv_path, "w") as f:
                                f.write("domain\n")
                                f.write(f"{domain}\n")
                    elif "." in user_input:
                        domain = user_input
                        domains.append(domain)
                        with open(csv_path, "w") as f:
                            f.write("domain\n")
                            f.write(f"{domain}\n")
                    else:
                        print("[INFO] Exiting. No CSV loaded and no domain entered.")
                        return
                else:
                    with open(csv_path, "r") as f:
                        domains = [line.strip() for line in f if line.strip() and not line.lower().startswith("domain")]
        
            all_results = []
            for domain in domains:
                result = evaluate_domain(domain)
                print_results([result])
                all_results.append(result)
            
            save_html_report(all_results)
                
if __name__ == "__main__":
    main()
