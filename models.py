class DeviceDTO:
    """Objeto de Transferência de Dados para representar dispositivos na rede."""
    def __init__(self, ip: str, mac: str, vendor: str = "Desconhecido"):
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.open_ports = []
        self.is_vulnerable = False

    def to_dict(self):
        """Converte o objeto para dicionário (útil para relatórios JSON)."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "open_ports": self.open_ports,
            "is_vulnerable": self.is_vulnerable
        }