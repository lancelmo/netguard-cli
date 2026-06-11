# Estágio 1: Build e Instalação de Dependências
FROM python:3.10-slim AS builder
WORKDIR /app

# Instala as ferramentas de compilação de redes no Linux temporariamente
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Estágio 2: Imagem de Execução
FROM python:3.10-slim AS runner
WORKDIR /app

# Instala apenas o driver de execução de captura de pacotes
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copia o ambiente pronto do estágio anterior e o código fonte
COPY --from=builder /opt/venv /opt/venv
COPY . .

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]