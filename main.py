import requests
import socket
import ssl
import dns.resolver
from datetime import datetime, timezone
from tabulate import tabulate

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
        print(f"[DEBUG] SSL error for {domain}: {e}")
        return "SSL handshake failed"
    except socket.timeout:
        print(f"[DEBUG] Timeout trying to connect to {domain}")
        return "Connection timeout"
    except socket.gaierror:
        print(f"[DEBUG] DNS resolution failed for {domain}")
        return "DNS resolution failed"
    except Exception as e:
        print(f"[DEBUG] General error for {domain}: {e}")
        return f"Error: {e}"

def check_mail_records(domain):
    results = {"SPF": "No", "DKIM": "No", "DMARC": "No"}
    
    try:
        # SPF
        spf_records = dns.resolver.resolve(domain, 'TXT')
        for rdata in spf_records:
            for txt_string in rdata.strings:
                if b"v=spf1" in txt_string:
                    results["SPF"] = "Yes"

        # DKIM - default._domainkey
        dkim_domain = f"default._domainkey.{domain}"
        try:
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in dkim_records:
                for txt_string in rdata.strings:
                    if b"v=DKIM1" in txt_string:
                        results["DKIM"] = "Yes"
        except:
            pass  # DKIM not found, leave as "No"

        # DMARC - _dmarc
        dmarc_domain = f"_dmarc.{domain}"
        try:
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in dmarc_records:
                for txt_string in rdata.strings:
                    if b"v=DMARC1" in txt_string:
                        results["DMARC"] = "Yes"
        except:
            pass  # DMARC not found, leave as "No"

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

def evaluate_domain(domain):
    is_up = check_http_status(domain)
    ssl_days_left = get_ssl_expiry(domain) if is_up else None

    print(f"[DEBUG] Checking {domain} | Up: {is_up} | SSL Days Left: {ssl_days_left}")

    mail_results = check_mail_records(domain)
    header_results = check_security_headers(domain)

    return {
        "Domain": domain,
        "Up": "Yes" if is_up else "No",
        "SSL Days Left": ssl_days_left if ssl_days_left is not None else "-",
        "SPF": mail_results["SPF"],
        "DKIM": mail_results["DKIM"],
        "DMARC": mail_results["DMARC"],
        "Strict-Transport-Security": header_results["Strict-Transport-Security"],
        "X-Frame-Options": header_results["X-Frame-Options"],
        "X-XSS-Protection": header_results["X-XSS-Protection"],
        "Content-Security-Policy": header_results["Content-Security-Policy"],
        "Blacklist Status": check_dnsbl(domain) 
    }

    
def check_dnsbl(domain):
    dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net"
    ]
    try:
        ip = socket.gethostbyname(domain)
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for dnsbl in dnsbls:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                socket.gethostbyname(query)
                return "Listed"
            except socket.gaierror:
                continue  # Not listed in this DNSBL
        return "Clean"
    except Exception as e:
        return f"Error: {e}"

def print_results(results):
    for r in results:
        print("=" * 50)
        print(f"Domain: {r['Domain']}")
        print(f"Up?: {r['Up']}")
        print(f"Cert Expiry (days): {r['SSL Days Left']}")
        print(f"SPF: {r['SPF']}")
        print(f"DKIM: {r['DKIM']}")
        print(f"DMARC: {r['DMARC']}")
        print(f"Strict-Transport-Security: {r['Strict-Transport-Security']}")
        print(f"X-Frame-Options: {r['X-Frame-Options']}")
        print(f"X-XSS-Protection: {r['X-XSS-Protection']}")
        print(f"Content-Security-Policy: {r['Content-Security-Policy']}")
        print(f"Blacklist Status: {r['Blacklist Status']}")
        print("=" * 50)
        print()

def main():
    domain = input("Enter the domain you want to check: ")
    domains = [domain]
    results = [evaluate_domain(domain) for domain in domains]

    headers = [
        "Domain", "Up?", "Cert Expiry (days)", "SPF", "DKIM", "DMARC",
        "Strict-Transport-Security", "X-Frame-Options",
        "X-XSS-Protection", "Content-Security-Policy"
    ]

    table = [[
        r["Domain"], r["Up"], r["SSL Days Left"], r["SPF"], r["DKIM"], r["DMARC"],
        r["Strict-Transport-Security"], r["X-Frame-Options"],
        r["X-XSS-Protection"], r["Content-Security-Policy"]
    ] for r in results]
   
    print_results(results)	

if __name__ == "__main__":
    main()
