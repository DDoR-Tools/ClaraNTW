import socket
import subprocess
import platform
import re
import time
from tqdm import tqdm
from threading import Thread

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    subprocess.run(["pip", "install", "colorama", "tqdm"])
    from colorama import Fore, Style, init
    init(autoreset=True)

def display_banner():
    banner = r"""
  ____ _                  
 / ___| | __ _ _ __ __ _ 
| |   | |/ _` | '__/ _` |
| |___| | (_| | | | (_| |
 \____|_|\__,_|_|  \__,_|
    """
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(Fore.YELLOW + Style.BRIGHT + "Welcome to Clara, a network scanner\n")

def resolve_ip(domain):
    try:
        ipv4 = socket.gethostbyname(domain)
        ipv6 = None
        try:
            ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            ipv6 = ipv6_info[0][4][0] if ipv6_info else None
        except socket.gaierror:
            pass
        return ipv4, ipv6
    except socket.gaierror:
        return None, None

def scan_ports(ip, ports):
    open_ports = []
    print(Fore.GREEN + f"\nScan des ports pour {ip}...\n")
    for port in tqdm(ports, desc="Scan en cours", unit="port", ncols=80):
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
            time.sleep(0.5)  # Pause pour rendre l'exécution plus lente et naturelle
        except (socket.timeout, ConnectionRefusedError):
            pass
    return open_ports

def describe_ports(ports):
    descriptions = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP Alternatif"
    }
    return {port: descriptions.get(port, "Inconnu") for port in ports}

def save_results(domain, ip, open_ports):
    filename = f"{domain}_scan_results.txt"
    with open(filename, "w") as file:
        file.write(f"Résultats pour {domain} ({ip})\n")
        file.write("=" * 40 + "\n")
        for port, desc in describe_ports(open_ports).items():
            file.write(f"Port {port}: {desc}\n")
    print(Fore.YELLOW + f"Résultats sauvegardés dans {filename}\n")

def main():
    display_banner()

    while True:
        domain = input(Fore.CYAN + Style.BRIGHT + "Entrez un domaine (ou 'exit' pour quitter) : ").strip()
        if domain.lower() == "exit":
            print(Fore.MAGENTA + "Au revoir!")
            break

        ipv4, ipv6 = resolve_ip(domain)
        if not ipv4 and not ipv6:
            print(Fore.RED + "Erreur : Domaine introuvable.\n")
            continue

        print(Fore.GREEN + f"\nRésolution d'IP pour {domain}:")
        if ipv4:
            print(Fore.YELLOW + f" - IPv4 : {ipv4}")
        if ipv6:
            print(Fore.YELLOW + f" - IPv6 : {ipv6}")

        choice = input(Fore.CYAN + "\nVoulez-vous scanner (1) des ports spécifiques ou (2) des ports communs ? ").strip()
        if choice == "1":
            port_input = input(Fore.CYAN + "Entrez les ports à scanner (ex: 22,80,443) : ").strip()
            ports = [int(p) for p in port_input.split(",") if p.isdigit()]
        else:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]

        ip_to_scan = ipv4 or ipv6
        open_ports = scan_ports(ip_to_scan, ports)

        if open_ports:
            print(Fore.GREEN + f"\nPorts ouverts sur {domain} ({ip_to_scan}):")
            for port, desc in describe_ports(open_ports).items():
                print(Fore.YELLOW + f" - Port {port}: {desc}")
        else:
            print(Fore.RED + f"\nAucun port ouvert trouvé sur {domain} ({ip_to_scan}).")

        save_results(domain, ip_to_scan, open_ports)

if __name__ == "__main__":
    main()
