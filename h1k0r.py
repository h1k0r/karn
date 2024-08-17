import argparse
import requests
import dns.resolver
import dns.query
import dns.zone
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Set
import socket

# Command-line argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Subdomain Discovery Tool with Multiple Features")
    parser.add_argument("-d", "--domain", required=True, help="Target domain for subdomain discovery")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for brute-forcing subdomains (optional)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use for brute-forcing")
    parser.add_argument("-l", "--threat-level", action="store_true", help="Enable threat level analysis for discovered subdomains")
    parser.add_argument("--custom-domains", nargs='+', help="Add custom domains to the discovery process")
    parser.add_argument("--zone-transfer", action="store_true", help="Attempt DNS zone transfers for domain")
    parser.add_argument("--reverse-dns", action="store_true", help="Perform reverse DNS lookups")
    return parser.parse_args()

# Clean domain format
def clean_domain(domain: str) -> str:
    if domain.startswith('http://'):
        domain = domain[len('http://'):]
    if domain.startswith('https://'):
        domain = domain[len('https://'):]
    return domain.strip('/')

# DNS Zone Transfer
def attempt_zone_transfer(domain: str) -> Set[str]:
    try:
        transfer_dns_server = '8.8.8.8'
        zone = dns.zone.from_xfr(dns.query.xfr(transfer_dns_server, domain))
        return set(node for node in zone.nodes.keys())
    except Exception as e:
        print(f"Zone transfer failed: {e}")
        return set()

# Reverse DNS Lookups
def reverse_dns_lookup(ip: str) -> Set[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10  # Increased timeout
        return set(dns.resolver.resolve_address(ip))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        print(f"Reverse DNS lookup failed: {e}")
        return set()

# Brute-Forcing Subdomains
def brute_force_subdomains(domain: str, wordlist: Optional[Set[str]]) -> Set[str]:
    discovered_subdomains = set()
    if wordlist is None:
        return discovered_subdomains
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_subdomain = {executor.submit(check_subdomain, domain, sub): sub for sub in wordlist}
        for future in future_to_subdomain:
            subdomain = future.result()
            if subdomain:
                discovered_subdomains.add(subdomain)
    return discovered_subdomains

def check_subdomain(domain: str, subdomain: str) -> Optional[str]:
    url = f"http://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return f"{subdomain}.{domain}"
    except (requests.ConnectionError, dns.resolver.NXDOMAIN) as e:
        print(f"Error checking subdomain {subdomain}.{domain}: {e}")
    return None

# Query Certificate Transparency Logs
def query_certificate_transparency(domain: str) -> Set[str]:
    url = f"https://crt.sh/?q={domain}&output=json"
    response = requests.get(url)
    subdomains = set()
    if response.status_code == 200:
        data = response.json()
        for entry in data:
            if 'name_value' in entry:
                subdomains.add(entry['name_value'])
    return subdomains

# Threat Level Analysis (Dummy Implementation)
def threat_level_analysis(subdomains: Set[str]) -> dict:
    threat_levels = {}
    for subdomain in subdomains:
        threat_levels[subdomain] = "Low"  # Placeholder for real threat intelligence
    return threat_levels

# Main function to combine all techniques
def main(domain: str, wordlist: Optional[Set[str]] = None):
    domain = clean_domain(domain)
    all_discovered_subdomains = set()

    # DNS Zone Transfer
    if args.zone_transfer:
        zone_subdomains = attempt_zone_transfer(domain)
        all_discovered_subdomains.update(zone_subdomains)

    # Brute-forcing
    if wordlist:
        brute_forced_subdomains = brute_force_subdomains(domain, wordlist)
        all_discovered_subdomains.update(brute_forced_subdomains)

    # Certificate Transparency
    ct_subdomains = query_certificate_transparency(domain)
    all_discovered_subdomains.update(ct_subdomains)

    # Custom Domains Handling
    if args.custom_domains:
        for custom_domain in args.custom_domains:
            custom_domain = clean_domain(custom_domain)
            discovered_subdomains = brute_force_subdomains(custom_domain, wordlist)
            all_discovered_subdomains.update(discovered_subdomains)

    # Reverse DNS Lookups if requested
    if args.reverse_dns:
        for subdomain in all_discovered_subdomains:
            try:
                ip = dns.resolver.resolve(subdomain, 'A')[0].to_text()
                reverse_domains = reverse_dns_lookup(ip)
                print(f"[+] Reverse DNS for {subdomain}: {reverse_domains}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
                print(f"Reverse DNS lookup failed for {subdomain}: {e}")

    # Threat Level Analysis (Optional)
    if args.threat_level:
        threat_levels = threat_level_analysis(all_discovered_subdomains)
        print("\n[+] Threat Levels:")
        for subdomain, level in threat_levels.items():
            print(f"{subdomain}: {level}")

    print(f"\n[+] Discovered {len(all_discovered_subdomains)} subdomains:")
    for subdomain in all_discovered_subdomains:
        print(subdomain)

if __name__ == "__main__":
    args = parse_args()
    wordlist = None
    if args.wordlist:
        with open(args.wordlist, 'r') as file:
            wordlist = set(file.read().splitlines())
    main(args.domain, wordlist)