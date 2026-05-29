import json
from datetime import datetime

class ReportManager:
    def __init__(self, export_path="auditoria_cyber_intelligence.json"):
        self.export_path = export_path
        
        # Base de dados idêntica e centralizada para resolução local de OUI no JSON
        self.vendor_prefixes = {
            # DELL
            "00:14:22": ("Dell Inc.", "Notebook/Desktop/Server"),
            "d4:be:d9": ("Dell Inc.", "Notebook/Desktop"),
            "1c:72:1d": ("Dell Inc.", "Notebook/Desktop"),
            "00:21:70": ("Dell Inc.", "Notebook"),

            # APPLE (iPhones, MacBooks, Mac, Roteadores em tethering)
            "00:17:f2": ("Apple, Inc.", "MacBook/iPhone"),
            "8c:85:90": ("Apple, Inc.", "iPhone/iPad/AppleWatch"),
            "f4:f1:5a": ("Apple, Inc.", "MacBook/iMac"),
            "b4:18:d1": ("Apple, Inc.", "iPhone/iPad"),
            "9a:60:ca": ("Apple, Inc.", "iPhone Hotspot / Apple Device"),

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

            # PLACAS DE REDE GENÉRICAS
            "30:9c:23": ("Intel Corporate", "Wi-Fi/Ethernet Card"),
            "a4:4b:d5": ("Intel Corporate", "Intel Wi-Fi 6"),
            "00:e0:4c": ("Realtek Semiconductor", "Ethernet Adapter"),
            "b8:27:eb": ("Raspberry Pi Foundation", "IoT/Microcomputador"),

            # ROTEADORES / INFRAESTRUTURA
            "50:c7:bf": ("TP-Link", "Router/Wi-Fi Extender"),
            "00:17:88": ("Philips Hue", "Smart Home IoT Hub"),
            "bc:a5:11": ("Cisco Systems", "Network Switch/Router")
        }

    def _identificar_fabricante_local(self, mac_address):
        """Busca o OUI localmente para o relatório caso o DTO venha vazio ou Desconhecido."""
        if not mac_address or mac_address == "Desconhecido":
            return "Desconhecido"
        
        mac_limpo = mac_address.lower().replace("-", ":")
        prefixo = ":".join(mac_limpo.split(":")[:3])
        
        fabricante, _ = self.vendor_prefixes.get(prefixo, ("Desconhecido", ""))
        return fabricante

    def _obter_dica_seguranca(self, porta, banner_detectado=""):
        """Mapeamento avançado com correlação de vulnerabilidades estilo Nikto Spider e MITRE ATT&CK."""
        banner_str = banner_detectado if banner_detectado else "Serviço Ativo (Banner Oculto)"
        
        mitre_mapping = {
            21: {
                "servico": "FTP (File Transfer Protocol)",
                "mitre_tactique": "TA0006 - Credential Access",
                "mitre_technique": "T1040 - Network Sniffing",
                "impacto_seguranca": "Protocolo herdado e inseguro. Credenciais e dados trafegam em texto claro. Cruzando com a heurística do Nikto, a exposição deste serviço sem criptografia de transporte (SSL/TLS) permite a interceptação e roubo de sessões de arquivos brutas."
            },
            22: {
                "servico": "SSH (Secure Shell)",
                "mitre_tactique": "TA0001 - Initial Access",
                "mitre_technique": "T1133 - External Remote Services",
                "impacto_seguranca": f"Canal de gerência remota criptografado. Identificado via Banner Grabbing: [{banner_str}]. Representa risco crítico de segurança caso utilize credenciais fracas ou desatualizadas suscetíveis a ataques de força bruta automatizados."
            },
            80: {
                "servico": "HTTP (Hypertext Transfer Protocol)",
                "mitre_tactique": "TA0007 - Discovery",
                "mitre_technique": "T1059 - Command and Scripting Interpreter",
                "impacto_seguranca": f"Servidor Web ativo detectado via Banner: [{banner_str}]. Correlação Nikto Spider: O uso de servidores HTTP sem patches atualizados expõe vetores para ataques ativos de injeção de código (XSS/SQL Injection) e quebra de parâmetros de busca (Path Traversal), caso as aplicações hospedadas possuam falhas de higienização de input."
            },
            443: {
                "servico": "HTTPS (HTTP Secure)",
                "mitre_tactique": "TA0007 - Discovery",
                "mitre_technique": "T1046 - Network Service Scanning",
                "impacto_seguranca": f"Canal Web Seguro TLS/SSL ativo: [{banner_str}]. Embora criptografado, o Nikto auditaria a força das cifras. Recomenda-se mitigar riscos de engenharia reversa de rotas inspecionando periodicamente a validade dos certificados digitais."
            },
            445: {
                "servico": "SMB (Server Message Block)",
                "mitre_tactique": "TA0008 - Lateral Movement",
                "mitre_technique": "T1210 - Exploitation of Remote Services",
                "impacto_seguranca": "Porta de compartilhamento Windows exposta na rede local. Vetor histórico e altamente crítico para exploits de execução remota de código e movimentação lateral automatizada (ex: exploits estilo EternalBlue utilizados por campanhas globais de Ransomware)."
            },
            3306: {
                "servico": "MySQL Database Server",
                "mitre_tactique": "TA0009 - Collection",
                "mitre_technique": "T1145 - Data Information Store",
                "impacto_seguranca": "Instância de Banco de Dados acessível diretamente via rede. Uma exposição inadequada pode permitir ataques de injeção de queries ou exfiltração em massa de tabelas confidenciais por falhas severas de autenticação (Broken Authentication)."
            }
        }
        
        return mitre_mapping.get(porta, {
            "servico": "Serviço Customizado",
            "mitre_tactique": "TA0007 - Discovery",
            "mitre_technique": "N/A - Custom Port Service",
            "impacto_seguranca": f"Porta customizada ativa detectada: [{banner_str}]. Recomenda-se aplicar políticas restritivas de Firewall baseadas no Princípio do Menor Privilégio, fechando conexões que não possuam justificativa de negócio clara."
        })

    def save_to_json(self, devices):
        dispositivos_com_portas_abertas_e_possiveis_falhas = []
        dispositivos_seguros = []

        for dev in devices:
            dados = dev.to_dict()
            
            # Se o vendor veio genérico ou nulo, tenta resolver com a nossa tabela OUI robusta
            if dados.get('vendor') == "Desconhecido" or not dados.get('vendor'):
                dados['vendor'] = self._identificar_fabricante_local(dados.get('mac'))
            
            if dados['open_ports']:
                # MUDANÇA TÉCNICA: Se tem porta aberta expondo serviços vulneráveis, vira True!
                dados['is_vulnerable'] = True
                
                analise = []
                portas_limpas = []
                
                for item_porta in dados['open_ports']:
                    p = item_porta["porta"]
                    banner = item_porta["banner_detectado"]
                    portas_limpas.append(p)
                    
                    inteligencia_mitre = self._obter_dica_seguranca(p, banner)
                    analise.append({
                        "porta_analisada": p,
                        "banner_coletado": banner if banner else "Serviço Ativo (Banner Oculto)",
                        "analise_heuristica_vulnerabilidade": inteligencia_mitre
                    })
                
                dados['open_ports'] = portas_limpas
                dados['analise_de_risco_automatizada'] = analise
                dispositivos_com_portas_abertas_e_possiveis_falhas.append(dados)
            else:
                dados['is_vulnerable'] = False
                dispositivos_seguros.append(dados)

        conteudo_final = {
            "auditoria_threat_intelligence": {
                "projeto": "NetGuard Advanced Cyber Defense Engine",
                "executado_em": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "total_ativos_mapeados": len(devices),
                "framework_referencia": "MITRE ATT&CK Matrix v14 + Nikto Spider Vulnerability Correlation"
            },
            "ameacas_detectadas_dispositivos_com_portas_abertas": dispositivos_com_portas_abertas_e_possiveis_falhas,
            "dispositivos_seguros_sem_exposicao_aparente": dispositivos_seguros
        }

        try:
            with open(self.export_path, "w", encoding="utf-8") as f:
                json.dump(conteudo_final, f, indent=4, ensure_ascii=False)
            return self.export_path
        except Exception:
            return None