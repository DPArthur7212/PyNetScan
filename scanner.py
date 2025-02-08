import socket
import threading
import argparse


def scan_port(target, port):
    """Tente de se connecter à un port donné et affiche s'il est ouvert."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout pour éviter les blocages
            if s.connect_ex((target, port)) == 0:
                print(f"[+] Port {port} ouvert")
    except Exception as e:
        pass


def scan_ports(target, ports):
    """Scanne une liste de ports sur la cible donnée."""
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner de ports en Python")
    parser.add_argument("-t", "--target", required=True, help="Adresse IP de la cible")
    parser.add_argument("-p", "--ports", required=True, help="Plage de ports à scanner, ex: 20-100")

    args = parser.parse_args()

    # Convertir l'entrée des ports en liste
    start_port, end_port = map(int, args.ports.split("-"))
    port_range = range(start_port, end_port + 1)

    print(f"[INFO] Scan de {args.target} sur les ports {start_port}-{end_port}...")
    scan_ports(args.target, port_range)