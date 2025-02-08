import socket
import threading
import argparse
import json
import scapy.all as scapy
from tabulate import tabulate

def scan_port(target, port, results, stealth):
    """Tente de se connecter à un port donné et affiche s'il est ouvert."""
    try:
        if stealth:
            pkt = scapy.IP(dst=target)/scapy.TCP(dport=port, flags="S")
            response = scapy.sr1(pkt, timeout=1, verbose=False)
            if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
                service = socket.getservbyport(port) if port in range(1, 65536) else "Unknown"
                results.append([port, service])
                print(f"[+] Port {port} ouvert ({service})")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Timeout pour éviter les blocages
                if s.connect_ex((target, port)) == 0:
                    service = socket.getservbyport(port) if port in range(1, 65536) else "Unknown"
                    results.append([port, service])
                    print(f"[+] Port {port} ouvert ({service})")
    except Exception:
        pass

def scan_ports(target, ports, stealth):
    """Scanne une liste de ports sur la cible donnée."""
    threads = []
    results = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port, results, stealth))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    return results

def save_results_to_json(target, results, output_file):
    """Sauvegarde les résultats du scan en format JSON."""
    with open(output_file, 'w') as f:
        json.dump({"target": target, "open_ports": results}, f, indent=4)
    print(f"[INFO] Résultats sauvegardés dans {output_file}")

def generate_html_report(target, results, output_file):
    """Génère un rapport HTML basé sur les résultats du scan."""
    html_content = f"""
    <html>
    <head><title>Rapport de Scan</title></head>
    <body>
        <h1>Rapport de Scan pour {target}</h1>
        <table border='1'>
            <tr><th>Port</th><th>Service</th></tr>
            {''.join(f'<tr><td>{port}</td><td>{service}</td></tr>' for port, service in results)}
        </table>
    </body>
    </html>
    """
    with open(output_file, 'w') as f:
        f.write(html_content)
    print(f"[INFO] Rapport HTML généré : {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner de ports en Python")
    parser.add_argument("-t", "--target", required=True, help="Adresse IP de la cible")
    parser.add_argument("-p", "--ports", required=True, help="Plage de ports à scanner, ex: 20-100")
    parser.add_argument("-o", "--output", required=False, help="Fichier JSON de sortie", default="scan_results.json")
    parser.add_argument("-s", "--stealth", action="store_true", help="Mode furtif (scan SYN)")
    parser.add_argument("-r", "--report", required=False, help="Générer un rapport HTML", default=None)
    
    args = parser.parse_args()
    
    # Convertir l'entrée des ports en liste
    start_port, end_port = map(int, args.ports.split("-"))
    port_range = range(start_port, end_port + 1)
    
    print(f"[INFO] Scan de {args.target} sur les ports {start_port}-{end_port}...")
    results = scan_ports(args.target, port_range, args.stealth)
    
    if args.output:
        save_results_to_json(args.target, results, args.output)
    
    if args.report:
        generate_html_report(args.target, results, args.report)
    
    # Affichage en tableau CLI
    print(tabulate(results, headers=["Port", "Service"], tablefmt="grid"))
