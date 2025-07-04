import dns.resolver
import socket
import csv
import time
from colorama import Fore, Style, init

init(autoreset=True)

# === SETTINGS ===
INPUT_FILE = "list.txt" # UBAH BAGIAN INI JADI LIST DOMAIN KALIAN
OUTPUT_FILE = "hasil_scan.csv"  # CONTOH OUTPUT HASIL SCAN .CSV

# === UTILITIES ===

def get_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=3)
        return [str(rdata) for rdata in answers]
    except:
        return []

def get_nameservers(domain):
    return get_records(domain, 'NS')

def get_mx_records(domain):
    return get_records(domain, 'MX')

def get_a_record(domain):
    return get_records(domain, 'A')

def is_resolvable(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False

def is_domain_active(domain):
    """Cek apakah domain aktif via DNS SOA record (tanpa WHOIS)."""
    try:
        dns.resolver.resolve(domain, 'SOA', lifetime=3)
        return True
    except:
        return False

def scan_domain(domain):
    results = []
    ns_list = get_nameservers(domain)
    mx_list = get_mx_records(domain)
    a_list = get_a_record(domain)

    if not ns_list:
        print(Fore.YELLOW + f"⚠️  {domain}: Tidak ditemukan NS")
        results.append([domain, "-", "-", "-", "-", "-", "No NS Found"])
        return results

    for ns in ns_list:
        resolvable = "Resolvable" if is_resolvable(ns) else "Unresolvable"
        ns_domain = ".".join(ns.split('.')[-2:])  # contoh: ns1.abandoned.com → abandoned.com

        domain_status = "REGISTERED" if is_domain_active(ns_domain) else "AVAILABLE"

        print(f"🔍 {domain} → NS: {Fore.CYAN + ns} | {Fore.GREEN if resolvable == 'Resolvable' else Fore.RED}{resolvable} | " +
              (Fore.GREEN if domain_status == "REGISTERED" else Fore.RED + domain_status))

        mx_info = ','.join(mx_list) if mx_list else "-"
        a_info = ','.join(a_list) if a_list else "-"

        results.append([domain, ns, resolvable, domain_status, mx_info, a_info])
        time.sleep(0.3)  # optional: slow down to prevent DNS overload

    return results

def main():
    try:
        with open(INPUT_FILE, 'r') as file:
            domains = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"File {INPUT_FILE} tidak ditemukan.")
        return

    all_results = []

    print(Fore.CYAN + f"🌐 Memulai scan {len(domains)} domain...\n")

    for domain in domains:
        result = scan_domain(domain)
        all_results.extend(result)

    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Domain", "Nameserver", "Resolvable", "NS Domain Status (via SOA)", "MX Record", "A Record"])
        writer.writerows(all_results)

    print(Fore.GREEN + f"\n✅ Scan selesai. Hasil disimpan di: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
