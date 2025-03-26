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
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now(timezone.utc)).days
                return days_left
    except Exception:
        return None

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

def evaluate_domain(domain):
    is_up = check_http_status(domain)
    ssl_days_left = get_ssl_expiry(domain) if is_up else None
    mail_results = check_mail_records(domain)

    return {
        "Domain": domain,
        "Up": "Yes" if is_up else "No",
        "SSL Days Left": ssl_days_left if ssl_days_left is not None else "-",
        "SPF": mail_results["SPF"],
        "DKIM": mail_results["DKIM"],
        "DMARC": mail_results["DMARC"]
    }

def main():
    domain = input("Enter the domain you want to check: ")
    domains = [domain]		
    results = [evaluate_domain(domain) for domain in domains]

    table = [[r["Domain"], r["Up"], r["SSL Days Left"],r["SPF"],r["DKIM"],r["DMARC"]] for r in results]
    print(tabulate(table, headers=["Domain", "Up?", "Cert Expiry (days)","SPF","DKIM","DMARC"], tablefmt="grid"))

if __name__ == "__main__":
    main()
