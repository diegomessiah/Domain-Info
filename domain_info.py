import whois
import dns.resolver
import ssl
import socket
import requests

def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        print("[-] Error al obtener información WHOIS del dominio:", e)
        return None

def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [str(rdata) for rdata in answers]
        return ip_addresses
    except Exception as e:
        print("[-] Error al obtener registros DNS del dominio:", e)
        return []

def get_subdomains(domain):
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            "APIKEY": "YOUR_SECURITYTRAILS_API_KEY"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdomains = response.json()["subdomains"]
            return subdomains
        else:
            print("[-] Error al obtener subdominios:", response.status_code)
            return []
    except Exception as e:
        print("[-] Error al obtener subdominios:", e)
        return []

def get_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print("[-] Error al obtener el certificado SSL:", e)
        return None

def check_open_ports(ip_address):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]  # Puertos comunes a verificar

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Configura el tiempo de espera de conexión a 1 segundo
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"[-] Error al verificar puerto {port}: {e}")

    return open_ports

def main():
    domain = input("Introduce el nombre de dominio a consultar: ")

    # Obtener información WHOIS
    print("[*] Obtener información WHOIS...")
    whois_info = get_whois_info(domain)
    if whois_info:
        print("[+] Información WHOIS:")
        print(whois_info)

    # Obtener registros DNS
    print("[*] Obtener registros DNS...")
    dns_records = get_dns_records(domain)
    if dns_records:
        print("[+] Registros DNS:")
        for ip in dns_records:
            print("    -", ip)

    # Obtener subdominios
    print("[*] Obtener subdominios...")
    subdomains = get_subdomains(domain)
    if subdomains:
        print("[+] Subdominios:")
        for subdomain in subdomains:
            print("    -", subdomain + '.' + domain)  # Incluimos el dominio principal al imprimir el subdominio
            subdomain_ips = get_dns_records(subdomain + '.' + domain)
            if subdomain_ips:
                for subdomain_ip in subdomain_ips:
                    open_ports = check_open_ports(subdomain_ip)
                    if open_ports:
                        print("        [+] Puertos abiertos en", subdomain_ip)
                        print("            -", open_ports)
                    else:
                        print("        [-] No se encontraron puertos abiertos en", subdomain_ip)
            else:
                print("        [-] No se encontraron registros DNS para el subdominio")

    # Obtener certificado SSL
    print("[*] Obtener información del certificado SSL...")
    ssl_cert = get_ssl_certificate(domain)
    if ssl_cert:
        print("[+] Certificado SSL:")
        print(ssl_cert)

if __name__ == "__main__":
    main()
