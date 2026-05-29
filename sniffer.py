from scapy.all import sniff, TCP, UDP, IP
import sys

class SnifferModule:
    def __init__(self):
        self.keep_sniffing = True
        # Base de dados para identificação de hardware (OUI/Vendor)
        # Base de dados expandida com OUIs reais do mercado global
        # Base de dados expandida com OUIs reais das maiores fabricantes do mercado
        self.vendor_prefixes = {
            # DELL
            "00:14:22": ("Dell Inc.", "Notebook/Desktop/Server"),
            "d4:be:d9": ("Dell Inc.", "Notebook/Desktop"),
            "1c:72:1d": ("Dell Inc.", "Notebook/Desktop"),
            "00:21:70": ("Dell Inc.", "Notebook"),

            # APPLE (iPhones, MacBooks, iPads)
            "00:17:f2": ("Apple, Inc.", "MacBook/iPhone"),
            "8c:85:90": ("Apple, Inc.", "iPhone/iPad/AppleWatch"),
            "f4:f1:5a": ("Apple, Inc.", "MacBook/iMac"),
            "b4:18:d1": ("Apple, Inc.", "iPhone/iPad"),

            # SAMSUNG
            "2c:98:11": ("Samsung Electronics", "Mobile/SmartTV"),
            "1c:5a:3e": ("Samsung Electronics", "SmartTV"),
            "bc:72:b1": ("Samsung Electronics", "Mobile/Galaxy"),
            "94:8b:c1": ("Samsung Electronics", "Mobile/Galaxy"),

            # XIAOMI / MI
            "1c:99:4c": ("Xiaomi Communications", "Mobile/POCO/Redmi"),
            "50:ec:50": ("Xiaomi Communications", "Mobile/POCO/Redmi"),
            "64:cc:2e": ("Xiaomi Communications", "Mobile/SmartDevices"),
            "d4:61:9d": ("Xiaomi Communications", "Mobile/POCO/Redmi"),

            # MOTOROLA / LENOVO
            "00:15:a8": ("Motorola Mobility", "Mobile/Moto"),
            "a4:70:d6": ("Motorola Mobility", "Mobile/Moto"),
            "60:be:b5": ("Motorola Mobility", "Mobile/Moto"),
            "00:50:56": ("Lenovo", "Notebook/ThinkPad"),

            # ACER
            "00:1e:68": ("Acer Inc.", "Notebook/Desktop"),
            "c0:38:96": ("Acer Inc.", "Notebook/Aspire"),

            # PLACAS DE REDE GENÉRICAS (Muitas vezes embutidas em Dell, Acer e HP)
            "30:9c:23": ("Intel Corporate", "Wi-Fi/Ethernet Card"),
            "a4:4b:d5": ("Intel Corporate", "Intel Wi-Fi 6"),
            "00:e0:4c": ("Realtek Semiconductor", "Ethernet Adapter"),
            "b8:27:eb": ("Raspberry Pi Foundation", "IoT/Microcomputador"),

            # ROTEADORES / INFRAESTRUTURA
            "50:c7:bf": ("TP-Link", "Router/Wi-Fi Extender"),
            "00:17:88": ("Philips Hue", "Smart Home IoT Hub"),
            "bc:a5:11": ("Cisco Systems", "Network Switch/Router"),
            "9a:60:ca": ("Router/Gateway", "Network Device Generico")
        }

    def _identificar_dispositivo(self, mac_address):
        """Analisa o endereço MAC para inferir o fabricante e tipo de hardware."""
        if not mac_address:
            return "Desconhecido", "Desconhecido"
        
        # Padroniza para minúsculas e substitui hífens por dois pontos se houver
        mac_limpo = mac_address.lower().replace("-", ":")
        
        # Pega os 3 primeiros bytes do MAC (ex: 2c:98:11)
        prefixo = ":".join(mac_limpo.split(":")[:3])
        
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
            sys.stdout.flush() # Força o terminal a entregar o texto rápido

    def run_live_sniff(self):
        """Roda o sniffer capturando todo o tráfego até o usuário pressionar CTRL+C."""
        self.keep_sniffing = True
        try:
            # Sem filtro, para capturar IP genérico (HTTP, HTTPS, DNS, etc.)
            sniff(
                filter="ip", 
                prn=self.analyze_packet, 
                store=0, 
                stop_filter=lambda x: not self.keep_sniffing
            )
        except KeyboardInterrupt:
            self.keep_sniffing = False
            print("\n[+] Monitoramento ao vivo encerrado pelo operador.")