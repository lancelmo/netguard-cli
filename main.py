import socket
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Imports das tuas classes (Módulos)
from scanner import ScannerEngine
from sniffer import SnifferModule
from reports import ReportManager

console = Console()

def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return f"{'.'.join(ip.split('.')[:-1])}.0/24"
    except Exception:
        return "127.0.0.1/24"

class NetGuardController:
    def __init__(self):
        self.is_running = True
        self.network_range = get_local_network()
        
        # Inicialização dos objetos conforme a UML
        self.scanner = ScannerEngine(self.network_range)
        self.sniffer = SnifferModule()
        self.reporter = ReportManager()
        self.found_devices = []

    def display_menu(self):
        console.print("") 
        console.print(Panel(
            f"[bold red]☠ NETGUARD CYBER DEFENSE NETWORK ENGINE v1.2 ☠[/bold red]\n"
            f"[bold white]Target Range Local Network:[/bold white] [cyan]{self.network_range}[/cyan] | "
            f"[bold white]Engine Status:[/bold white] [green]READY[/green]",
            expand=False,
            border_style="red"
        ))
        
        # Criação de um menu em formato de tabela
        menu_table = Table(show_header=True, header_style="bold blue", border_style="dim")
        menu_table.add_column("Cód", style="yellow", justify="center")
        menu_table.add_column("Módulo Operacional", style="bold white")
        menu_table.add_column("Descrição Técnica do Alvo")
        
        menu_table.add_row("1", "[cyan]RECON SCAN[/cyan]", "Mapeamento ativo de hosts locais via pacotes ARP Broadcast")
        menu_table.add_row("2", "[magenta]PORT SCAN & GRABBING[/magenta]", "Varredura TCP com extração de banners de serviço estilo Nikto")
        menu_table.add_row("3", "[green]THREAT INTELLIGENCE REPORT[/green]", "Gera auditoria classificada integrada com a matriz MITRE ATT&CK")
        menu_table.add_row("4", "[yellow]LIVE TRAFFIC SNIFFER[/yellow]", "Monitoramento passivo em tempo real de protocolos em texto claro")
        menu_table.add_row("0", "[bold red]TERMINATE ENGINE[/bold red]", "Finalizar a execução do sistema de auditoria")
        
        console.print(menu_table)

    def run(self):
        while self.is_running:
            self.display_menu()
            choice = console.input("\n[bold yellow]Selecione uma diretriz de operação: [/bold yellow]")

            if choice == "1":
                self.perform_network_scan()
            elif choice == "2":
                self.perform_port_scan()
            elif choice == "3":
                self.export_report()
            elif choice == "4":
                self.perform_live_sniffing()
            elif choice == "0":
                self.is_running = False
            else:
                console.print("[red]Opção inválida![/red]")

    def perform_network_scan(self):
        with console.status("[bold green]Iniciando varredura ARP Broadcast..."):
            self.found_devices = self.scanner.arp_scan()
        
        table = Table(title="Ativos de Rede Mapeados")
        table.add_column("Endereço IP", style="cyan")
        table.add_column("Endereço MAC Physical", style="magenta")
        for dev in self.found_devices:
            table.add_row(dev.ip, dev.mac)
        console.print(table)

    def perform_port_scan(self):
        # Validação de segurança: o usuário precisa ter mapeado a rede primeiro
        if not self.found_devices:
            console.print("[bold red]Erro Operacional: Nenum host na memória. Execute o RECON SCAN (Opção 1) primeiro.[/bold red]")
            return

        console.print(Panel(
            f"[bold magenta]INICIANDO VARREDURA EM MASSA (AUTOMATED PORT SCAN)[/bold magenta]\n"
            f"Alvos detectados em memória: [yellow]{len(self.found_devices)} dispositivo(s)[/yellow]\n"
            f"Realizando Banner Grabbing estilo Nikto Spider...",
            border_style="magenta"
        ))

        # Loop automático por todos os IPs que a Opção 1 encontrou
        for dev in self.found_devices:
            console.print(f"\n[bold cyan]» Escaneando Host:[/bold cyan] {dev.ip} [{dev.mac}]")
            
            with console.status(f"[bold green]Conectando e extraindo banners de {dev.ip}..."):
                # Dispara o scanner para o IP atual do loop
                ports_info = self.scanner.port_scan(dev.ip)
                # Vincula o resultado de portas diretamente no DTO do dispositivo atual
                dev.open_ports = ports_info
            
            # Monta a tabela de resultados individual para este host
            table = Table(title=f"Resultado Técnico para: {dev.ip}", border_style="dim")
            table.add_column("Porta", style="yellow", justify="center")
            table.add_column("Banner de Identificação Coletado", style="green")
            
            if ports_info:
                for item in ports_info:
                    table.add_row(str(item["porta"]), item["banner_detectado"])
                console.print(table)
            else:
                console.print("[dim white]Nenhum serviço comum exposto nesta máquina.[/dim white]")
                
        console.print("\n[bold green]✓ Varredura em massa concluída com sucesso![/bold green]")

    def perform_live_sniffing(self):
        console.print(Panel("[bold red]INICIANDO MONITORAMENTO PASSIVO PROMISCUO[/bold red]\nAnalisando pacotes brutos. Pressione [bold white]CTRL+C[/bold white] para abortar a escuta e retornar."))
        self.sniffer.run_live_sniff()

    def export_report(self):
        if not self.found_devices:
            console.print("[red]Erro Operacional: Nenhuma árvore de ativos na memória. Execute o Mapeamento primeiro.[/red]")
            return
        
        path = self.reporter.save_to_json(self.found_devices)
        if path:
            console.print(f"[bold green]Sucesso! Relatório de Inteligência contra Ameaças gerado em: {path}[/bold green]")

if __name__ == "__main__":
    app = NetGuardController()
    app.run()