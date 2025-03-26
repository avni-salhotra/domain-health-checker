import requests
import socket
import ssl
import dns.resolver
import ipaddress
import subprocess
import whois
import shutil
import argparse
from datetime import datetime, timezone


def clean_field(value):
    return value if value not in [None, "Unknown", "-", "Error"] else "N/A"


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
    except ssl.SSLError as e:
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


def get_domain_expiry(domain):
    try:
        w = whois.whois(domain)
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if expiry_date is None:
            return "Unknown"
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        days_left = (expiry_date - datetime.now(timezone.utc)).days
        return days_left
    except Exception as e:
        return f"Error: {e}"


def check_http_to_https(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        final_url = response.url
        if final_url.startswith("https://"):
            return "Yes"
        else:
            return "No"
    except Exception as e:
        return f"Error: {e}"


def check_tech_stack(domain):
    stack_info = {"Server": "Unknown", "X-Powered-By": "Unknown"}
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        if "Server" in response.headers:
            stack_info["Server"] = response.headers["Server"]
        if "X-Powered-By" in response.headers:
            stack_info["X-Powered-By"] = response.headers["X-Powered-By"]
        if "wp-content" in response.text or "wp-includes" in response.text:
            stack_info["Framework"] = "WordPress"
        elif '<meta name="generator"' in response.text:
            stack_info["Framework"] = "Detected from meta tag"
        else:
            stack_info["Framework"] = "Unknown"
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


def install_go_tool(tool_name, go_get_url):
    if shutil.which(tool_name):
        print(f"[INFO] {tool_name} is already installed.")
        return
    print(f"[INFO] {tool_name} not found. Attempting to install using Go.")
    try:
        subprocess.run(["go", "install", go_get_url], check=True, timeout=60)
    except Exception as e:
        print(f"[ERROR] Could not install {tool_name}: {e}")


def enumerate_subdomains(domain, tool="subfinder"):
    if shutil.which(tool) is None:
        return [f"{tool} not installed"]
    try:
        result = subprocess.run(
            [tool, "-d", domain, "-silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            return [f"{tool} error: {result.stderr.strip()}"]
        subdomains = result.stdout.strip().split("\n")
        return [sub for sub in subdomains if sub]
    except Exception as e:
        return [f"Error: {e}"]


def evaluate_domain(domain):
    is_up = check_http_status(domain)
    ssl_days_left = get_ssl_expiry(domain) if is_up else None
    domain_expiry_days = get_domain_expiry(domain)
    mail_results = check_mail_records(domain)
    header_results = check_security_headers(domain)
    tech_results = check_tech_stack(domain)
    dns_results = check_dns_provider(domain)
    subdomains = enumerate_subdomains(domain)
    return {
        "Domain": domain,
        "Up": "Yes" if is_up else "No",
        "SSL Days Left": ssl_days_left if ssl_days_left is not None else "-",
        "Domain Expiry (days)": domain_expiry_days,
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
        "A Record IP": dns_results["A Record IP"],
        "NS Records": ", ".join(dns_results["NS Records"]),
        "DNS Provider Guess": dns_results["DNS Provider Guess"],
        "AAAA Record IP": dns_results["AAAA Record IP"],
        "Reverse DNS": reverse_dns_lookup(dns_results["A Record IP"]),
        "SSL Config Status": check_ssl_config(domain),
        "Subdomains": subdomains
    }


def print_results(results):
    for r in results:
        print("=" * 50)
        for key, value in r.items():
            print(f"{key}: {clean_field(value)}")
        print("=" * 50)
        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", action="store_true", help="Install dependencies like subfinder/amass")
    args = parser.parse_args()

    if args.setup:
        install_go_tool("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        install_go_tool("amass", "github.com/owasp-amass/amass/v3/...@latest")
        return

    domain = input("Enter the domain you want to check: ")
    results = [evaluate_domain(domain)]
    print_results(results)


if __name__ == "__main__":
    main()
