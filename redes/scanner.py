import socket  # Biblioteca para conexões de rede (base do scanner)
from concurrent.futures import ThreadPoolExecutor  # Para rodar várias tarefas ao mesmo tempo (threads)

#serviços
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

# Função para transformar site em IP
def resolve_target(target):
    try:
        return socket.gethostbyname(target)  # Resolve domínio para IP
    except:
        print("Erro ao resolver host")  # Caso não consiga
        return None

# Função para tentar capturar o banner do serviço
def grab_banner(sock, port):
    try:
        # Se for HTTP (porta 80), precisa enviar requisição
        if port == 80:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")

        # FTP e SSH geralmente respondem automaticamente
        elif port == 21 or port == 22:
            return sock.recv(1024).decode().strip()

        # Para outros casos, tenta apenas ler resposta
        return sock.recv(1024).decode().strip()

    except:
        return "Sem banner"  # Se não receber nada ou der erro

# Função que escaneia uma única porta
def scan_port(ip, port):
    sock = socket.socket()  # Cria socket (conexão)
    sock.settimeout(1)  # Tempo máximo de espera (1 segundo)

    try:
        # Tenta conectar no IP e porta
        result = sock.connect_ex((ip, port))

        # Se resultado for 0 → porta aberta
        if result == 0:
            # Pega nome do serviço (ou "Desconhecido")
            service = COMMON_PORTS.get(port, "Desconhecido")

            # Tenta pegar banner do serviço
            banner = grab_banner(sock, port)

            # Retorna informações da porta aberta
            return (port, service, banner)

    except:
        pass  # Ignora erros

    finally:
        sock.close()  # Fecha conexão sempre

    return None  # Retorna nada se porta estiver fechada

# Função principal para escanear um alvo completo
def scan_target(target):
    ip = resolve_target(target)  # Resolve o IP
    if not ip:
        return  # Sai se não conseguiu resolver

    print(f"\nEscaneando {target} ({ip})...\n")

    # Cria pool de threads (100 conexões simultâneas)
    with ThreadPoolExecutor(max_workers=100) as executor:
        # Escaneia portas de 1 a 1024 em paralelo
        results = executor.map(lambda p: scan_port(ip, p), range(1, 1025))

    found = False  # Flag para saber se encontrou portas abertas

    # Percorre resultados
    for result in results:
        if result:
            found = True
            port, service, banner = result

            # Mostra porta aberta
            print(f"[+] Porta {port} ABERTA ({service})")

            # Mostra banner (se tiver)
            print(f"    ↳ Banner: {banner}\n")

    # Se nenhuma porta aberta foi encontrada
    if not found:
        print("Nenhuma porta aberta encontrada")

# Loop principal (permite testar vários alvos)
while True:
    target = input("\nDigite o IP/site (ou 'sair'): ")

    # Condição para sair do programa
    if target.lower() == "sair":
        break

    # Executa o scanner
    scan_target(target)