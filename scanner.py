import socket
import threading
import argparse
import json

def scan_port(target, port, results):
    """Tente de se connecter à un port donné et affiche s'il est ouvert."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout pour éviter les blocages
            if s.connect_ex((target, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                print(f"[+] Port {port} ouvert ({service})")
                results[port] = service
    except Exception as e:
        pass

def scan_ports(target, ports):
    """Scanne une liste de ports sur la cible donnée."""
    threads = []
    results = {}
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port, results))
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner de ports en Python")
    parser.add_argument("-t", "--target", required=True, help="Adresse IP de la cible")
    parser.add_argument("-p", "--ports", required=True, help="Plage de ports à scanner, ex: 20-100")
    parser.add_argument("-o", "--output", required=False, help="Fichier JSON de sortie", default="scan_results.json")
    
    args = parser.parse_args()
    
    # Convertir l'entrée des ports en liste
    start_port, end_port = map(int, args.ports.split("-"))
    port_range = range(start_port, end_port + 1)
    
    print(f"[INFO] Scan de {args.target} sur les ports {start_port}-{end_port}...")
    results = scan_ports(args.target, port_range)
    
    if args.output:
        save_results_to_json(args.target, results, args.output)
