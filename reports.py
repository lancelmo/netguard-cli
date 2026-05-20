import json
from datetime import datetime

class ReportManager:
    def __init__(self, export_path="auditoria_cyber_intelligence.json"):
        self.export_path = export_path

    def _obter_dica_seguranca(self, porta, banner_detectado=""):
        """Mapeamento avançado com correlação de vulnerabilidades estilo Nikto Spider e MITRE ATT&CK."""
        
        # Limpa o banner para facilitar a exibição
        banner_str = banner_detectado if banner_detectado else "Desconhecido"
        
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
            
            if dados['open_ports']:
                analise = []
                portas_limpas = []
                
                for item_porta in dados['open_ports']:
                    p = item_porta["porta"]
                    banner = item_porta["banner_detectado"]
                    portas_limpas.append(p)
                    
                    # Passamos o banner detectado para enriquecer a dica de segurança dinamicamente
                    inteligencia_mitre = self._obter_dica_seguranca(p, banner)
                    analise.append({
                        "porta_analisada": p,
                        "banner_coletado": banner,
                        "analise_heuristica_vulnerabilidade": inteligencia_mitre
                    })
                
                dados['open_ports'] = portas_limpas
                dados['analise_de_risco_automatizada'] = analise
                dispositivos_com_portas_abertas_e_possiveis_falhas.append(dados)
            else:
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