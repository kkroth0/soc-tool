import re
import requests
import json
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from dotenv import load_dotenv
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io
from PIL import Image as PILImage

# Inicializa o console rich
console = Console()

# Carrega as chaves de API
load_dotenv()
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')

# Configuração dos estilos do PDF
styles = getSampleStyleSheet()
title_style = ParagraphStyle(
    'CustomTitle',
    parent=styles['Heading1'],
    fontSize=24,
    spaceAfter=30
)
heading_style = ParagraphStyle(
    'CustomHeading',
    parent=styles['Heading2'],
    fontSize=18,
    spaceAfter=12
)
normal_style = styles['Normal']

def extrair_ips(texto: str) -> List[str]:
    """Extrai IPs válidos do texto"""
    linhas = texto.strip().split('\n')
    ips = []
    
    for linha in linhas:
        linha = linha.strip()
        if not linha:
            continue
        
        # Pega primeira palavra da linha (ignora números/frequências após o IP)
        possivel_ip = linha.split()[0].strip()
        
        if validar_ip(possivel_ip):
            ips.append(possivel_ip)
    
    return list(dict.fromkeys(ips))  # Remove duplicatas

def validar_ip(ip: str) -> bool:
    """Valida um endereço IP"""
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in partes)

def formatar_kql(ips: List[str], tipo: str = 'both') -> str:
    """Formata IPs para KQL"""
    if not ips:
        return ""
        
    joined = ' or '.join(f'"{ip}"' for ip in ips)
    
    if tipo == 'source':
        return f'source.ip: ({joined})'
    elif tipo == 'destination':
        return f'destination.ip: ({joined})'
    else:
        return f'(source.ip: ({joined}) or destination.ip: ({joined}))'

def check_virustotal(ip: str) -> Dict:
    """Verifica IP no VirusTotal"""
    if not VT_API_KEY:
        return {"error": "API Key do VirusTotal não configurada"}
        
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats['harmless'],
                "error": None
            }
    except Exception as e:
        return {"error": str(e)}
    
    return {"error": "Falha na consulta ao VirusTotal"}

def check_abuseipdb(ip: str) -> Dict:
    """Verifica IP no AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        return {"error": "API Key do AbuseIPDB não configurada"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "confidence_score": data['abuseConfidenceScore'],
                "total_reports": data['totalReports'],
                "last_reported": data.get('lastReportedAt', 'N/A'),
                "domain": data.get('domain', 'N/A'),
                "isp": data.get('isp', 'N/A'),
                "error": None
            }
    except Exception as e:
        return {"error": str(e)}
    
    return {"error": "Falha na consulta ao AbuseIPDB"}

def check_ipinfo(ip: str) -> Dict:
    """Verifica IP no IPInfo"""
    if not IPINFO_API_KEY:
        return {"error": "API Key do IPInfo não configurada"}
        
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {
                "hostname": data.get('hostname', 'N/A'),
                "city": data.get('city', 'N/A'),
                "region": data.get('region', 'N/A'),
                "country": data.get('country', 'N/A'),
                "org": data.get('org', 'N/A'),
                "postal": data.get('postal', 'N/A'),
                "timezone": data.get('timezone', 'N/A'),
                "error": None
            }
    except Exception as e:
        return {"error": str(e)}
    
    return {"error": "Falha na consulta ao IPInfo"}

def save_detailed_report(ips: List[str], filename: str = "scan_report.txt") -> str:
    """Gera um relatório detalhado com todas as análises"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("SOC Forge - Relatório de Análise de IPs\n")
        f.write(f"Data do relatório: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for ip in ips:
            # Coleta informações
            vt_result = check_virustotal(ip)
            abuse_result = check_abuseipdb(ip)
            info_result = check_ipinfo(ip)
            
            # Determina status
            is_malicious = (
                (not vt_result.get("error") and vt_result.get("malicious", 0) > 0) or
                (not abuse_result.get("error") and abuse_result.get("confidence_score", 0) >= 50)
            )
            
            f.write(f"IP: {ip}\n")
            f.write(f"Status: {'MALICIOSO' if is_malicious else 'LIMPO'}\n")
            
            # VirusTotal
            f.write("\nVirusTotal:\n")
            if not vt_result.get("error"):
                f.write(f"  Malicioso: {vt_result.get('malicious', 0)}\n")
                f.write(f"  Suspeito: {vt_result.get('suspicious', 0)}\n")
                f.write(f"  Limpo: {vt_result.get('harmless', 0)}\n")
            else:
                f.write(f"  {vt_result['error']}\n")
            
            # AbuseIPDB
            f.write("\nAbuseIPDB:\n")
            if not abuse_result.get("error"):
                f.write(f"  Score de Confiança: {abuse_result.get('confidence_score', 0)}%\n")
                if abuse_result.get("total_reports"):
                    f.write(f"  Total de Reports: {abuse_result['total_reports']}\n")
            else:
                f.write(f"  {abuse_result['error']}\n")
            
            # Localização
            f.write("\nLocalização:\n")
            if not info_result.get("error"):
                if info_result.get("city"):
                    f.write(f"  Cidade: {info_result['city']}\n")
                if info_result.get("country"):
                    f.write(f"  País: {info_result['country']}\n")
                if info_result.get("hostname") != "N/A":
                    f.write(f"  Hostname: {info_result['hostname']}\n")
            else:
                f.write(f"  {info_result['error']}\n")
            
            # Links
            f.write("\nLinks para análise:\n")
            f.write(f"VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}\n")
            f.write(f"AbuseIPDB: https://www.abuseipdb.com/check/{ip}\n")
            f.write(f"AlienVault OTX: https://otx.alienvault.com/indicator/ip/{ip}\n")
            f.write("-" * 50 + "\n\n")
    
    return filename

def display_menu():
    """Exibe menu de opções"""
    menu = """
[bold cyan]O que você deseja fazer?[/bold cyan]

[green]1.[/green] Listar IPs encontrados
[green]2.[/green] Analisar IPs no VirusTotal
[green]3.[/green] Analisar IPs no AbuseIPDB
[green]4.[/green] Análise de Geolocalização (IPInfo)
[green]5.[/green] Análise Completa (Todos os serviços)
[green]6.[/green] Gerar query KQL (source.ip)
[green]7.[/green] Gerar query KQL (destination.ip)
[green]8.[/green] Gerar query KQL (ambos)
[green]9.[/green] Gerar Relatório Detalhado
[green]10.[/green] Gerar Relatório em PDF
[green]11.[/green] Sair
"""
    console.print(Panel(menu, title="SOC Forge", border_style="cyan"))

def display_virustotal_results(ips: List[str]):
    """Exibe resultados do VirusTotal"""
    table = Table(
        title="Análise VirusTotal",
        box=box.DOUBLE_EDGE,
        title_style="bold magenta",
        border_style="blue"
    )
    table.add_column("IP", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Malicioso", justify="center")
    table.add_column("Suspeito", justify="center")
    table.add_column("Limpo", justify="center")
    
    for ip in ips:
        resultado = check_virustotal(ip)
        if resultado.get("error"):
            table.add_row(ip, "[red]Erro[/red]", "-", "-", "-")
        else:
            status = "[red]MALICIOSO[/red]" if resultado["malicious"] > 0 else "[green]LIMPO[/green]"
            table.add_row(
                ip,
                status,
                str(resultado["malicious"]),
                str(resultado["suspicious"]),
                str(resultado["harmless"])
            )
    
    console.print(table)

def display_abuseipdb_results(ips: List[str]):
    """Exibe resultados do AbuseIPDB"""
    table = Table(
        title="Análise AbuseIPDB",
        box=box.DOUBLE_EDGE,
        title_style="bold magenta",
        border_style="blue"
    )
    table.add_column("IP", style="cyan")
    table.add_column("Score", style="bold")
    table.add_column("Total Reports", justify="center")
    table.add_column("ISP", style="green")
    table.add_column("Domain", style="green")
    
    for ip in ips:
        resultado = check_abuseipdb(ip)
        if resultado.get("error"):
            table.add_row(ip, "[red]Erro[/red]", "-", "-", "-")
        else:
            score = resultado["confidence_score"]
            score_color = "red" if score >= 50 else "green"
            table.add_row(
                ip,
                f"[{score_color}]{score}%[/{score_color}]",
                str(resultado["total_reports"]),
                resultado["isp"],
                resultado["domain"]
            )
    
    console.print(table)

def display_ipinfo_results(ips: List[str]):
    """Exibe resultados do IPInfo"""
    table = Table(
        title="Análise IPInfo",
        box=box.DOUBLE_EDGE,
        title_style="bold magenta",
        border_style="blue"
    )
    table.add_column("IP", style="cyan")
    table.add_column("Localização", style="green")
    table.add_column("Organização", style="yellow")
    table.add_column("Hostname", style="blue")
    table.add_column("Timezone", style="magenta")
    
    for ip in ips:
        resultado = check_ipinfo(ip)
        if resultado.get("error"):
            table.add_row(ip, "[red]Erro[/red]", "-", "-", "-")
        else:
            location = f"{resultado['city']}, {resultado['region']}, {resultado['country']}"
            table.add_row(
                ip,
                location,
                resultado["org"],
                resultado["hostname"],
                resultado["timezone"]
            )
    
    console.print(table)

def display_complete_analysis(ips: List[str]):
    """Realiza e exibe análise completa"""
    console.print("\n[bold cyan]Iniciando análise completa...[/bold cyan]")
    display_virustotal_results(ips)
    console.print("")
    display_abuseipdb_results(ips)
    console.print("")
    display_ipinfo_results(ips)

def save_report(ips: List[str], filename: str = "scan_report.txt"):
    """Salva um relatório detalhado com todas as análises"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("SOC Forge - Relatório de Análise de IPs\n")
        f.write(f"Data do relatório: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        
        for ip in ips:
            # Coleta resultados
            vt_result = check_virustotal(ip)
            abuse_result = check_abuseipdb(ip)
            info_result = check_ipinfo(ip)
            
            # Determina status geral
            is_malicious = (
                (not vt_result.get("error") and vt_result.get("malicious", 0) > 0) or
                (not abuse_result.get("error") and abuse_result.get("confidence_score", 0) >= 50)
            )
            
            # Escreve informações no arquivo
            f.write(f"IP: {ip}\n")
            f.write(f"Status: {'MALICIOSO' if is_malicious else 'LIMPO'}\n\n")
            
            # VirusTotal
            f.write("VirusTotal:\n")
            if not vt_result.get("error"):
                f.write(f"  Malicioso: {vt_result.get('malicious', 0)}\n")
                f.write(f"  Suspeito: {vt_result.get('suspicious', 0)}\n")
                f.write(f"  Limpo: {vt_result.get('harmless', 0)}\n")
            else:
                f.write(f"  {vt_result['error']}\n")
            
            # AbuseIPDB
            f.write("\nAbuseIPDB:\n")
            if not abuse_result.get("error"):
                f.write(f"  Score de Confiança: {abuse_result.get('confidence_score', 0)}%\n")
                f.write(f"  Total de Reports: {abuse_result.get('total_reports', 0)}\n")
                if abuse_result.get("isp"):
                    f.write(f"  ISP: {abuse_result['isp']}\n")
                if abuse_result.get("domain") and abuse_result['domain'] != 'N/A':
                    f.write(f"  Domínio: {abuse_result['domain']}\n")
            else:
                f.write(f"  {abuse_result['error']}\n")
            
            # IPInfo
            f.write("\nLocalização:\n")
            if not info_result.get("error"):
                if info_result.get("city"):
                    f.write(f"  Cidade: {info_result['city']}\n")
                if info_result.get("region"):
                    f.write(f"  Região: {info_result['region']}\n")
                if info_result.get("country"):
                    f.write(f"  País: {info_result['country']}\n")
                if info_result.get("hostname") and info_result['hostname'] != 'N/A':
                    f.write(f"  Hostname: {info_result['hostname']}\n")
                if info_result.get("org") and info_result['org'] != 'N/A':
                    f.write(f"  Organização: {info_result['org']}\n")
            else:
                f.write(f"  {info_result['error']}\n")
            
            # Links para análise
            f.write("\nLinks para análise:\n")
            f.write(f"VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}\n")
            f.write(f"AbuseIPDB: https://www.abuseipdb.com/check/{ip}\n")
            f.write(f"AlienVault OTX: https://otx.alienvault.com/indicator/ip/{ip}\n")
            f.write("-" * 50 + "\n\n")
        
        f.write("\nFim do relatório\n")
    
    return filename

def generate_pdf_report(ips: List[str], results: Dict) -> str:
    """Gera um relatório PDF com os resultados da análise"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ip_analysis_report_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # Lista de elementos do PDF
    elements = []
    
    # Título
    elements.append(Paragraph("Relatório de Análise de IPs", title_style))
    elements.append(Spacer(1, 12))
    
    # Data do relatório
    elements.append(Paragraph(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 12))
    
    # Resumo
    elements.append(Paragraph("IPs Analisados:", heading_style))
    for ip in ips:
        elements.append(Paragraph(f"• {ip}", normal_style))
    elements.append(Spacer(1, 20))
    
    # Capturando saída do Rich Console
    console_capture = io.StringIO()
    console_file = Console(file=console_capture, force_terminal=True)
    
    for ip in ips:
        # Resultados do VirusTotal
        if "virustotal" in results[ip]:
            elements.append(Paragraph(f"Análise VirusTotal para {ip}:", heading_style))
            vt_result = results[ip]["virustotal"]
            
            if "error" not in vt_result:
                vt_table = Table(title=f"VirusTotal - {ip}", box=box.DOUBLE_EDGE)
                vt_table.add_column("Detecções Maliciosas", style="red")
                vt_table.add_column("Detecções Suspeitas", style="yellow")
                vt_table.add_row(str(vt_result["malicious"]), str(vt_result["suspicious"]))
                
                # Captura a tabela como texto
                console_file.print(vt_table)
                elements.append(Paragraph(console_capture.getvalue(), normal_style))
                console_capture.seek(0)
                console_capture.truncate()
            
            elements.append(Spacer(1, 12))
        
        # Resultados do AbuseIPDB
        if "abuseipdb" in results[ip]:
            elements.append(Paragraph(f"Análise AbuseIPDB para {ip}:", heading_style))
            abuse_result = results[ip]["abuseipdb"]
            
            if "error" not in abuse_result:
                abuse_table = Table(title=f"AbuseIPDB - {ip}", box=box.DOUBLE_EDGE)
                abuse_table.add_column("Pontuação de Abuso")
                abuse_table.add_column("Total de Relatórios")
                abuse_table.add_column("País")
                abuse_table.add_row(
                    str(abuse_result["abuseConfidenceScore"]),
                    str(abuse_result["totalReports"]),
                    abuse_result.get("countryCode", "N/A")
                )
                
                console_file.print(abuse_table)
                elements.append(Paragraph(console_capture.getvalue(), normal_style))
                console_capture.seek(0)
                console_capture.truncate()
            
            elements.append(Spacer(1, 12))
        
        # Resultados do IPInfo
        if "ipinfo" in results[ip]:
            elements.append(Paragraph(f"Análise IPInfo para {ip}:", heading_style))
            ipinfo_result = results[ip]["ipinfo"]
            
            if "error" not in ipinfo_result:
                ipinfo_table = Table(title=f"IPInfo - {ip}", box=box.DOUBLE_EDGE)
                ipinfo_table.add_column("País")
                ipinfo_table.add_column("Cidade")
                ipinfo_table.add_column("Organização")
                ipinfo_table.add_row(
                    ipinfo_result.get("country", "N/A"),
                    ipinfo_result.get("city", "N/A"),
                    ipinfo_result.get("org", "N/A")
                )
                
                console_file.print(ipinfo_table)
                elements.append(Paragraph(console_capture.getvalue(), normal_style))
                console_capture.seek(0)
                console_capture.truncate()
            
            elements.append(Spacer(1, 12))
    
    # Gera o PDF
    doc.build(elements)
    console.print(f"\n[green]Relatório PDF gerado:[/green] {filename}")
    return filename

def main():
    console.print("[bold cyan]SOC Forge - Analisador de IPs[/bold cyan]")
    console.print("\n[yellow]Cole a lista de IPs (pressione Enter duas vezes para finalizar):[/yellow]")
    
    linhas = []
    while True:
        try:
            linha = input()
            if not linha:
                break
            linhas.append(linha)
        except EOFError:
            break
    
    texto = '\n'.join(linhas)
    ips = extrair_ips(texto)
    
    if not ips:
        console.print("[red]Nenhum IP válido encontrado![/red]")
        return
    
    console.print(f"\n[green]IPs válidos encontrados:[/green] {len(ips)}")
    for i, ip in enumerate(ips, 1):
        console.print(f"[cyan]{i}.[/cyan] {ip}")
        
    # Dicionário para armazenar resultados de todas as análises
    results = {ip: {} for ip in ips}
    
    while True:
        display_menu()
        escolha = console.input("[bold cyan]Escolha uma opção:[/bold cyan] ")
        
        if escolha == "1":
            # Listar IPs
            table = Table(
                title="Lista de IPs Encontrados",
                box=box.DOUBLE_EDGE,
                title_style="bold magenta",
                border_style="blue"
            )
            table.add_column("Nº", style="cyan", justify="right")
            table.add_column("IP", style="green")
            
            for i, ip in enumerate(ips, 1):
                table.add_row(f"{i}", ip)
            
            console.print(table)
            
        elif escolha == "2":
            # Análise VirusTotal
            display_virustotal_results(ips)
            
        elif escolha == "3":
            # Análise AbuseIPDB
            display_abuseipdb_results(ips)
            
        elif escolha == "4":
            # Análise IPInfo
            display_ipinfo_results(ips)
            
        elif escolha == "5":
            # Análise Completa
            display_complete_analysis(ips)
            
        elif escolha == "6":
            query = formatar_kql(ips, "source")
            console.print("\n[bold green]Query KQL (source.ip):[/bold green]")
            console.print(query)
            
        elif escolha == "7":
            query = formatar_kql(ips, "destination")
            console.print("\n[bold green]Query KQL (destination.ip):[/bold green]")
            console.print(query)
            
        elif escolha == "8":
            query = formatar_kql(ips, "both")
            console.print("\n[bold green]Query KQL (source.ip e destination.ip):[/bold green]")
            console.print(query)
            
        elif escolha == "9":
            # Gerar Relatório Detalhado
            filename = save_detailed_report(ips)
            console.print(f"\n[green]Relatório detalhado salvo em: {filename}[/green]")
            
        elif escolha == "10":
            # Gerar Relatório em PDF
            results = {}
            for ip in ips:
                results[ip] = {
                    "virustotal": check_virustotal(ip),
                    "abuseipdb": check_abuseipdb(ip),
                    "ipinfo": check_ipinfo(ip)
                }
            
            filename = generate_pdf_report(ips, results)
            console.print(f"\n[green]Relatório PDF salvo em: {filename}[/green]")
        
        elif escolha == "11":
            console.print("[yellow]Encerrando programa...[/yellow]")
            break
            
        else:
            console.print("[red]Opção inválida![/red]")
        
        console.print("\nPressione Enter para continuar...")
        input()

if __name__ == "__main__":
    main()