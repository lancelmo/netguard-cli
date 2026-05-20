from scapy.all import ARP, Ether, srp, conf
import socket
from models import DeviceDTO

class ScannerEngine:
    def __init__(self, target_range: str):
        self.target_range = target_range

    def arp_scan(self):
        """Mapeia dispositivos ativos na rede local (RF01)."""
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=self.target_range)
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            devices.append(DeviceDTO(received.psrc, received.hwsrc))
        
        return devices

    def port_scan(self, ip: str, ports=[21, 22, 80, 443, 445, 3306]):
        """
        Verifica portas abertas (RF02) e realiza Banner Grabbing (Tática Nikto Spider)
        Retorna uma lista de dicionários com a porta e a identificação do serviço.
        """
        open_ports_summary = []
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0) # Ajustado para dar tempo ao Banner Grabbing
            
            if s.connect_ex((ip, port)) == 0:
                banner = "Serviço Ativo (Banner Oculto)"
                try:
                    # Envia uma requisição genérica para forçar o serviço a se identificar
                    if port in [80, 443]:
                        s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    else:
                        s.send(b"\r\n")
                    
                    resposta = s.recv(512).decode('utf-8', errors='ignore').strip()
                    if resposta:
                        # Filtra linhas comuns de identificação de servidores (Apache, Nginx, etc)
                        linhas_server = [line for line in resposta.split('\n') if "Server" in line or "version" in line.lower()]
                        if linhas_server:
                            banner = linhas_server[0].replace('\r', '').strip()
                        else:
                            banner = resposta.split('\n')[0].strip()[:50]
                except Exception:
                    pass
                
                # Guardamos a estrutura mapeada
                open_ports_summary.append({
                    "porta": port,
                    "banner_detectado": banner
                })
            s.close()
        return open_ports_summary