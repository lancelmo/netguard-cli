# NetGuard Cyber Defense Network Engine v1.2

Este projeto é uma ferramenta de auditoria de segurança e monitoramento de ativos de rede local em linha de comando (CLI), desenvolvida como projeto prático para a disciplina de **Engenharia de Software**. 

O sistema realiza varreduras ativas na rede, identifica serviços expostos coletando assinaturas de servidores (Banner Grabbing) e correlaciona as vulnerabilidades encontradas diretamente com a matriz global **MITRE ATT&CK v14** e o comportamento do **Nikto Spider**.

---

## 🛠️ Tecnologias e Pré-requisitos

Para que o projeto funcione corretamente, foi necessária a instalação e configuração dos seguintes componentes na máquina de desenvolvimento:

1. **Python 3.10+**: Linguagem de programação base utilizada no projeto.
2. **Npcap (Windows) / Libpcap (Linux/Mac)**: Biblioteca de captura de pacotes brutos. *Crucial para que a biblioteca Scapy consiga interagir diretamente com a placa de rede.*
3. **Git**: Ferramenta de controle de versão utilizada para gerenciar o código e publicar no GitHub.
4. **VS Code**: Ambiente de desenvolvimento (IDE) utilizado para codificação.

---

## 📦 Bibliotecas Utilizadas (Dependências)

O projeto foi construído utilizando o conceito de ambiente virtual isolado (`venv`) e depende das seguintes bibliotecas de terceiros:

* **Scapy (`pip install scapy`)**: Utilizada para manipulação, injeção e captura passiva de pacotes de rede (Camadas 2, 3 e 4).
* **Rich (`pip install rich`)**: Utilizada para construir a interface CLI avançada com tabelas, cores agressivas, painéis e barras de status em tempo real.

---

## 🚀 Como Instalar e Executar (Guia para a Equipe)

Siga os passos abaixo para clonar o repositório, configurar o ambiente e testar a aplicação na sua máquina local:

### 1. Clonar o Repositório
```bash
git clone [https://github.com/lancelmo/NetGuard-CLI.git](https://github.com/lancelmo/NetGuard-CLI.git)
cd NetGuard-CLI

2. Criar e Ativar o Ambiente Virtual (venv)
O ambiente virtual garante que as bibliotecas do projeto não entrem em conflito com outras versões do seu sistema.

No Windows (PowerShell):

python -m venv venv
.\venv\Scripts\activate

No Windows (Prompt de Comando - CMD):

python -m venv venv
venv\Scripts\activate

3. Instalar as Dependências
Com o ambiente (venv) ativo no seu terminal, instale os pacotes necessários:

Bash
pip install scapy rich

4. Executar a Aplicação
⚠️ IMPORTANTE (Requisito de Segurança): Como o software realiza escuta de tráfego na rede (Sniffing) e manipula pacotes brutos, o terminal do seu VS Code ou Prompt de Comando DEVE ser executado como Administrador.

Bash
python main.py

📋 Arquitetura de Módulos Operacionais

main.py: Controlador central da interface (NetGuardController). Gerencia o fluxo do menu e a persistência em memória.

scanner.py: Motor de varredura (ScannerEngine). Responsável pelo Reconhecimento ARP (RF01) e pelo Port Scanning com Banner Grabbing no estilo Nikto (RF02).

sniffer.py: Módulo de monitoramento contínuo (SnifferModule). Captura o tráfego IP de forma promíscua, identificando fabricantes via endereço MAC e classificando a segurança dos protocolos em tempo real (RF03/RF04).

reports.py: Gerenciador de relatórios (ReportManager). Classifica os dados e exporta uma auditoria em JSON integrada com inteligência contra ameaças baseada no Framework MITRE ATT&CK (RF05).

models.py: Contém o DTO (DeviceDTO) estruturado para transferência limpa de dados entre módulos.