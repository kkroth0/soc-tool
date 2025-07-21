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
    """Extrai IPs válidos de qualquer parte do texto, sem depender da posição."""
    padrao_ip = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    encontrados = re.findall(padrao_ip, texto)
    
    ips_validos = [ip for ip in encontrados if validar_ip(ip)]
    
    return list(dict.fromkeys(ips_validos))

def validar_ip(ip: str) -> bool:
    """Valida um endereço IP"""
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in partes)

def formatar_kql(ips: List[str], tipo: str = 'both') -> str:
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
    with open(filename, "w", encoding="utf-8") as f:
        f.write("SOC Forge - Relatório de Análise de IPs\n")
        f.write(f"Data do relatório: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for ip in ips:
            vt_result = check_virustotal(ip)
            abuse_result = check_abuseipdb(ip)
            info_result = check_ipinfo(ip)
            is_malicious = (
                (not vt_result.get("error") and vt_result.get("malicious", 0) > 0) or
                (not abuse_result.get("error") and abuse_result.get("confidence_score", 0) >= 50)
            )
            f.write(f"IP: {ip}\n")
            f.write(f"Status: {'MALICIOSO' if is_malicious else 'LIMPO'}\n")
            f.write("\nVirusTotal:\n")
            if not vt_result.get("error"):
                f.write(f"  Malicioso: {vt_result.get('malicious', 0)}\n")
                f.write(f"  Suspeito: {vt_result.get('suspicious', 0)}\n")
                f.write(f"  Limpo: {vt_result.get('harmless', 0)}\n")
            else:
                f.write(f"  {vt_result['error']}\n")
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
            f.write("\nLinks para análise:\n")
            f.write(f"VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}\n")
            f.write(f"AbuseIPDB: https://www.abuseipdb.com/check/{ip}\n")
            f.write(f"AlienVault OTX: https://otx.alienvault.com/indicator/ip/{ip}\n")
            f.write("-" * 50 + "\n\n")
        f.write("\nFim do relatório\n")
    return filename

def display_menu():
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
        
    results = {ip: {} for ip in ips}
    
    while True:
        display_menu()
        escolha = console.input("[bold cyan]Escolha uma opção:[/bold cyan] ").strip()
        
        if escolha == "1":
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
            # Sua função para exibir VirusTotal aqui, idem para outras opções
            pass  # Você pode completar aqui
            
        elif escolha == "11":
            console.print("[yellow]Encerrando programa...[/yellow]")
            break
            
        else:
            console.print("[red]Opção inválida![/red]")
        
        console.print("\nPressione Enter para continuar...")
        input()

if __name__ == "__main__":
    main()
