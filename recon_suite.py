import subprocess
import threading
import argparse
import os

def run_command(cmd, out_file):
    with open(out_file, 'w') as f:
        subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT)

def nmap_scan(target):
    print(f"[+] Running Nmap scan on {target}")
    run_command(['nmap', '-A', '-oN', 'nmap_results.txt', target], 'nmap_results.txt')
    print("[+] Nmap scan complete. Results saved to nmap_results.txt\n")

def bettercap_scan(iface):
    print(f"[+] Running Bettercap probe on {iface}")
    run_command(['bettercap', '-iface', iface, '-eval', 'net.probe on'], 'bettercap_results.txt')
    print("[+] Bettercap probe complete. Results saved to bettercap_results.txt\n")

def nikto_scan(target):
    print(f"[+] Running Nikto scan on {target}")
    run_command(['nikto', '-h', target, '-output', 'nikto_results.txt'], 'nikto_results.txt')
    print("[+] Nikto scan complete. Results saved to nikto_results.txt\n")

def amass_scan(domain):
    print(f"[+] Running Amass enumeration on {domain}")
    run_command(['amass', 'enum', '-d', domain, '-o', 'amass_results.txt'], 'amass_results.txt')
    print("[+] Amass enumeration complete. Results saved to amass_results.txt\n")

def harvester_scan(domain):
    print(f"[+] Running theHarvester on {domain}")
    run_command(['theHarvester', '-d', domain, '-b', 'all', '-f', 'harvester_results.html'], 'harvester_results.html')
    print("[+] theHarvester complete. Results saved to harvester_results.html\n")

def dirb_scan(url):
    print(f"[+] Running DIRB scan on {url}")
    run_command(['dirb', url, '-o', 'dirb_results.txt'], 'dirb_results.txt')
    print("[+] DIRB scan complete. Results saved to dirb_results.txt\n")

def gobuster_scan(url):
    wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
    print(f"[+] Running Gobuster scan on {url} with wordlist {wordlist}")
    run_command(['gobuster', 'dir', '-u', url, '-w', wordlist, '-o', 'gobuster_results.txt'], 'gobuster_results.txt')
    print("[+] Gobuster scan complete. Results saved to gobuster_results.txt\n")

def legion_scan(target):
    print(f"[+] Running Legion scan on {target}")
    run_command(['legion', '-n', target], 'legion_results.txt')
    print("[+] Legion scan complete. Results saved to legion_results.txt\n")

def mitmproxy_scan(iface):
    print(f"[+] Running mitmproxy on interface {iface}")
    run_command(['mitmproxy', '-i', iface, '--quiet', '-w', 'mitmproxy.log'], 'mitmproxy.log')
    print("[+] mitmproxy run complete. Capture saved to mitmproxy.log\n")

def ettercap_scan(iface):
    print(f"[+] Running Ettercap scan on interface {iface}")
    run_command(['ettercap', '-T', '-i', iface, '-M', 'arp:remote', '-q'], 'ettercap_results.txt')
    print("[+] Ettercap scan complete. Results saved to ettercap_results.txt\n")

def network_scan(iface):
    print("[*] Scanning local network for live hosts (this may take a minute)...")

    # Attempt import and subnet discovery
    try:
        import netifaces
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
        from ipaddress import IPv4Network
        subnet = str(IPv4Network(f"{ip}/{netmask}", strict=False))
        print(f"[*] Detected subnet: {subnet}")
    except Exception as e:
        print(f"[!] Could not auto-detect subnet: {e}")
        subnet = input("Enter subnet in CIDR notation (e.g., 192.168.1.0/24): ").strip()

    scan_file = "network_scan.txt"
    run_command(['nmap', '-sn', subnet], scan_file)

    live_hosts = []
    with open(scan_file) as f:
        ip = None
        mac = None
        for line in f:
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                if ip:
                    live_hosts.append({'ip': ip, 'mac': mac})
                ip = line.split()[-1]
                mac = None
            elif "MAC Address:" in line:
                mac = line.split('MAC Address:')[1].strip().split(' ')[0]
        # Add last host
        if ip:
            live_hosts.append({'ip': ip, 'mac': mac})

    if not live_hosts:
        print("[!] No hosts found on the network.\n")
    else:
        print("\nDiscovered hosts on the network:")
        for idx, host in enumerate(live_hosts, 1):
            mac_str = host['mac'] if host['mac'] else "N/A"
            print(f"{idx}. IP: {host['ip']}  MAC: {mac_str}")
        print()  # empty line
    return live_hosts

def interactive_menu():
    print('''Select an operation:
S. Scan network and list live targets
1. Nmap Scan
2. Bettercap Probe
3. Nikto Scan
4. Amass Enumeration
5. TheHarvester Recon
6. DIRB Scan
7. Gobuster Scan
8. Legion Scan
9. mitmproxy Scan
10. Ettercap Scan
11. Run All (Automated)
0. Exit
''')
    return input('Choice: ').strip()

def run_all(target, domain, iface, url):
    threads = []
    # Only add scans if parameters valid to avoid errors
    if target:
        threads.extend([
            threading.Thread(target=nmap_scan, args=(target,)),
            threading.Thread(target=nikto_scan, args=(target,)),
            threading.Thread(target=legion_scan, args=(target,))
        ])
    if domain:
        threads.extend([
            threading.Thread(target=amass_scan, args=(domain,)),
            threading.Thread(target=harvester_scan, args=(domain,))
        ])
    if iface:
        threads.extend([
            threading.Thread(target=bettercap_scan, args=(iface,)),
            threading.Thread(target=mitmproxy_scan, args=(iface,)),
            threading.Thread(target=ettercap_scan, args=(iface,))
        ])
    if url:
        threads.extend([
            threading.Thread(target=dirb_scan, args=(url,)),
            threading.Thread(target=gobuster_scan, args=(url,))
        ])

    if not threads:
        print("[!] No valid parameters provided for automated run.\n")
        return

    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("[+] Automated all scans completed.\n")

def main():
    parser = argparse.ArgumentParser(description='Powerful Network Recon/Attack Automation Suite')
    parser.add_argument('--target', help='Target IP/Host (optional, can be selected after network scan)')
    parser.add_argument('--domain', help='Target Domain (required for domain-based scans)')
    parser.add_argument('--iface', help='Network Interface (required for interface-based scans)')
    parser.add_argument('--url', help='Target URL (http[s]://host/) for web scans (required for web scanning)')
    args = parser.parse_args()

    selected_target = args.target  # May be None initially

    # Main loop
    while True:
        choice = interactive_menu()

        if choice.lower() == 's':  # Scan network
            if not args.iface:
                print("[!] Network interface (--iface) argument required to scan network.\n")
                continue
            hosts = network_scan(args.iface)
            if not hosts:
                continue
            print("Select a host by number to set as target, or press Enter to skip:")
            sel = input().strip()
            if sel.isdigit():
                idx = int(sel)
                if 1 <= idx <= len(hosts):
                    selected_target = hosts[idx - 1]['ip']
                    print(f"[+] Selected {selected_target} as target.\n")
                else:
                    print("[!] Invalid selection, target not changed.\n")
            else:
                print("[*] No target selected, continuing...\n")

        elif choice == '1':  # nmap scan
            if not selected_target:
                print("[!] No target set. Please scan the network (S) or specify --target.\n")
                continue
            nmap_scan(selected_target)

        elif choice == '2':  # bettercap
            if not args.iface:
                print("[!] Interface required for bettercap scan (--iface).\n")
                continue
            bettercap_scan(args.iface)

        elif choice == '3':  # nikto
            if not selected_target:
                print("[!] No target set. Please scan the network (S) or specify --target.\n")
                continue
            nikto_scan(selected_target)

        elif choice == '4':  # amass
            if not args.domain:
                print("[!] Domain required for Amass scan (--domain).\n")
                continue
            amass_scan(args.domain)

        elif choice == '5':  # theHarvester
            if not args.domain:
                print("[!] Domain required for theHarvester (--domain).\n")
                continue
            harvester_scan(args.domain)

        elif choice == '6':  # dirb
            if not args.url:
                print("[!] URL required for DIRB scan (--url).\n")
                continue
            dirb_scan(args.url)

        elif choice == '7':  # gobuster
            if not args.url:
                print("[!] URL required for Gobuster scan (--url).\n")
                continue
            gobuster_scan(args.url)

        elif choice == '8':  # legion
            if not selected_target:
                print("[!] No target set. Please scan the network (S) or specify --target.\n")
                continue
            legion_scan(selected_target)

        elif choice == '9':  # mitmproxy
            if not args.iface:
                print("[!] Interface required for mitmproxy (--iface).\n")
                continue
            mitmproxy_scan(args.iface)

        elif choice == '10':  # ettercap
            if not args.iface:
                print("[!] Interface required for ettercap (--iface).\n")
                continue
            ettercap_scan(args.iface)

        elif choice == '11':  # run all
            run_all(selected_target, args.domain, args.iface, args.url)

        elif choice == '0':
            print("Exiting...")
            break

        else:
            print("[!] Invalid choice, please try again.\n")

if __name__ == '__main__':
    main()
