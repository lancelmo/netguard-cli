from scapy.all import sniff, TCP, UDP, IP
import sys

class SnifferModule:
    def __init__(self):
        self.keep_sniffing = True
        # Base de dados educacional para identificação de hardware (OUI/Vendor)
        self.vendor_prefixes = {
            "8c:85:90": ("Apple", "Mobile/Desktop"),
            "2c:98:11": ("Samsung", "Mobile/SmartTV"),
            "9a:60:ca": ("Router/Gateway", "Network Device"),
            "30:9c:23": ("Intel", "Notebook/Desktop"),
            "74:da:da": ("Asustek", "Notebook/Desktop"),
            "d4:a0:2a": ("LG Electronics", "SmartTV/Mobile"),
            "00:11:32": ("Synology", "NAS Server/Storage")
        }

    def _identificar_dispositivo(self, mac_address):
        """Analisa o endereço MAC para inferir o fabricante e tipo de hardware."""
        if not mac_address:
            return "Desconhecido", "Desconhecido"
        
        # Pega os 3 primeiros bytes do MAC (ex: 2c:98:11)
        prefixo = ":".join(mac_address.lower().split(":")[:3])
        return self.vendor_prefixes.get(prefixo, ("Desconhecido", "Dispositivo Genérico"))

    def analyze_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_mac = packet.src if hasattr(packet, 'src') else None
            
            # Identifica o tipo de dispositivo com base no MAC de origem
            fabricante, tipo_hardware = self._identificar_dispositivo(src_mac)

            protocolo = "OUTRO"
            seguro = "N/A"
            style_color = "white"

            # Identificação de Protocolos de Camada de Transporte/Aplicação
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport

                if dport == 443 or sport == 443:
                    protocolo = "HTTPS"
                    seguro = "SEGURO (Criptografado)"
                elif dport == 80 or sport == 80:
                    protocolo = "HTTP"
                    seguro = "INSEGURO (Texto Claro)"
                elif dport == 22 or sport == 22:
                    protocolo = "SSH"
                    seguro = "SEGURO (Criptografado)"
                elif dport == 21 or sport == 21:
                    protocolo = "FTP"
                    seguro = "INSEGURO (Texto Claro)"
                elif dport == 445 or sport == 445:
                    protocolo = "SMB"
                    seguro = "CRÍTICO (Exposto)"
            
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if dport == 53 or sport == 53:
                    protocolo = "DNS"
                    seguro = "N/A (Consulta de Rede)"

            # Print formatado em tempo real
            # Altera o visual do log se detectar tráfego inseguro
            status_tag = "[ALERT]" if "INSEGURO" in seguro else "[TRAFFIC]"
            print(f"{status_tag} {src_ip} -> {dst_ip} | Proc: {protocolo} | Status: {seguro} | Origem: {fabricante} ({tipo_hardware})")
            sys.stdout.flush() # Força o terminal a cuspir o texto imediatamente

    def run_live_sniff(self):
        """Roda o sniffer capturando todo o tráfego até o usuário pressionar CTRL+C."""
        self.keep_sniffing = True
        try:
            # Filtro removido para capturar IP genérico (HTTP, HTTPS, DNS, etc.)
            sniff(
                filter="ip", 
                prn=self.analyze_packet, 
                store=0, 
                stop_filter=lambda x: not self.keep_sniffing
            )
        except KeyboardInterrupt:
            self.keep_sniffing = False
            print("\n[+] Monitoramento ao vivo encerrado pelo operador.")