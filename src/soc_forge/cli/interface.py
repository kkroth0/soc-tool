"""
Advanced SOC Analyst CLI Interface
Human-readable, context-aware interface designed for security operations
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.columns import Columns
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich import box
from typing import List, Dict, Any, Optional
import time
from datetime import datetime


class SOCInterface:
    """Advanced CLI interface for SOC analysts"""
    
    def __init__(self):
        self.console = Console(record=True)
        self.session_start = datetime.now()
        
    def display_banner(self):
        """Display SOC Forge banner with system info"""
        banner_text = """
===============================================================================
                              SOC FORGE v2.0                                  
                        Advanced IP Threat Intelligence                        
                                                                               
    Multi-Source Analysis    Rich Reporting    Fast Processing               
===============================================================================
        """
        
        self.console.print(banner_text, style="bold blue")
        self.console.print(f"Session started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}", 
                          style="dim", justify="center")
        self.console.print()
    
    def get_ip_input(self) -> str:
        """Get IP input from user with helpful guidance"""
        input_panel = Panel.fit(
            """[bold cyan]IP Input Methods Supported:[/bold cyan]
            
• [green]Single IP:[/green] 8.8.8.8
• [green]Multiple IPs (comma-separated):[/green] 8.8.8.8, 1.1.1.1, 208.67.222.222
• [green]Line-separated list:[/green] One IP per line
• [green]With ports:[/green] 192.168.1.1:80, 10.0.0.1:443
• [green]With prefixes:[/green] IP: 8.8.8.8, Address: 1.1.1.1
• [green]Mixed formats:[/green] Any combination of above

[dim]Tip: Press Enter twice when done, or Ctrl+C to cancel[/dim]""",
            title="SOC Target Input",
            border_style="cyan"
        )
        
        self.console.print(input_panel)
        self.console.print("\n[bold yellow]Enter your IP addresses or indicators:[/bold yellow]")
        
        lines = []
        try:
            while True:
                line = input(" ")
                if not line:
                    break
                lines.append(line)
        except (EOFError, KeyboardInterrupt):
            self.console.print("\n[yellow]Input cancelled[/yellow]")
            return ""
        
        return '\n'.join(lines)
    
    def display_parsing_results(self, parsing_result):
        """Display IP parsing results with detailed breakdown"""
        if not parsing_result.valid_ips:
            self.console.print(Panel(
                "[red]No valid public IPs found for analysis[/red]\n\n" +
                "[dim]This could mean:[/dim]\n" +
                "• Only private IPs were detected\n" +
                "• Invalid IP formats\n" +
                "• No IP addresses found in input",
                title="Parsing Results",
                border_style="red"
            ))
            
            if parsing_result.private_ips_found:
                self.console.print(f"\n[yellow]Private IPs found:[/yellow] {len(parsing_result.private_ips_found)}")
                for ip in parsing_result.private_ips_found[:5]:  # Show first 5
                    self.console.print(f"  • {ip}")
                if len(parsing_result.private_ips_found) > 5:
                    self.console.print(f"  ... and {len(parsing_result.private_ips_found) - 5} more")
            
            return False
        
        # Success panel
        stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stats_table.add_row("Valid Public IPs", f"[bold green]{len(parsing_result.valid_ips)}[/bold green]")
        stats_table.add_row("Private IPs Found", f"[yellow]{len(parsing_result.private_ips_found)}[/yellow]")
        stats_table.add_row("Invalid Entries", f"[red]{len(parsing_result.invalid_entries)}[/red]")
        stats_table.add_row("Duplicates Removed", f"[dim]{parsing_result.duplicates_removed}[/dim]")
        
        success_panel = Panel(
            stats_table,
            title="IP Parsing Results",
            border_style="green"
        )
        
        # IP list table
        ip_table = Table(title="Target IPs for Analysis", box=box.SIMPLE, border_style="blue")
        ip_table.add_column("#", style="cyan", width=4, justify="right")
        ip_table.add_column("IP Address", style="bold white")
        ip_table.add_column("Classification", style="green")
        
        for i, ip in enumerate(parsing_result.valid_ips, 1):
            ip_table.add_row(str(i), ip, "Public")
        
        self.console.print(success_panel)
        self.console.print(ip_table)
        return True
    
    def display_analysis_menu(self) -> str:
        """Display analysis options menu"""
        menu_options = [
            ("*", "1", "Quick Threat Assessment", "Fast analysis across all sources"),
            ("*", "2", "Comprehensive Analysis", "Deep dive with all available data"),
            ("*", "3", "GreyNoise Quick Check", "Rapid internet noise classification"),
            ("*", "4", "Malware & IOC Analysis", "ThreatFox and VirusTotal focus"),
            ("*", "5", "Geolocation & Network Intel", "IPInfo and network analysis"),
            ("*", "6", "Generate KQL Queries", "Security analytics queries"),
            ("*", "7", "Executive Summary Report", "High-level threat assessment"),
            ("*", "8", "Detailed Technical Report", "Complete analysis documentation"),
            ("*", "9", "Advanced Options", "Custom analysis settings"),
            ("*", "0", "Exit", "Close SOC Forge")
        ]
        
        menu_table = Table(box=box.ROUNDED, title="Analysis Options", border_style="cyan")
        menu_table.add_column("", width=3, style="bold")
        menu_table.add_column("Option", width=6, style="bold cyan")
        menu_table.add_column("Analysis Type", style="bold white")
        menu_table.add_column("Description", style="dim")
        
        for icon, num, name, desc in menu_options:
            menu_table.add_row(icon, num, name, desc)
        
        self.console.print(menu_table)
        return self.console.input("\n[bold cyan] Select analysis option:[/bold cyan] ")
    
    def display_analysis_progress(self, ips: List[str], sources: List[str]):
        """Display real-time analysis progress"""
        total_operations = len(ips) * len(sources)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=False
        ) as progress:
            
            main_task = progress.add_task(" Analyzing targets...", total=total_operations)
            
            for ip in ips:
                for source in sources:
                    progress.update(main_task, 
                                  description=f" Querying {source} for {ip}...",
                                  advance=1)
                    time.sleep(0.1)  # Simulate API calls
            
            progress.update(main_task, description=" Analysis complete!")
            time.sleep(0.5)
    
    def display_threat_summary(self, results):
        """Display high-level threat assessment summary"""
        total_ips = len(results)
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        
        threat_levels = {}
        
        for ip, result in results.items():
            # Handle both AnalysisResult objects and plain dictionaries
            data = result.data if hasattr(result, 'data') else result
            threat_score = self._calculate_threat_score(data)
            
            if threat_score >= 70:
                malicious_count += 1
                threat_levels[ip] = ("HIGH RISK", "red")
            elif threat_score >= 30:
                suspicious_count += 1  
                threat_levels[ip] = ("SUSPICIOUS", "yellow")
            else:
                clean_count += 1
                threat_levels[ip] = ("CLEAN", "green")
        
        # Summary statistics
        summary_table = Table(title="Threat Assessment Summary", box=box.SIMPLE, border_style="red")
        summary_table.add_column("Risk Level", style="bold")
        summary_table.add_column("Count", justify="center")
        summary_table.add_column("Percentage", justify="center")
        
        summary_table.add_row("HIGH RISK", str(malicious_count), f"{(malicious_count/total_ips)*100:.1f}%")
        summary_table.add_row("SUSPICIOUS", str(suspicious_count), f"{(suspicious_count/total_ips)*100:.1f}%")
        summary_table.add_row("CLEAN", str(clean_count), f"{(clean_count/total_ips)*100:.1f}%")
        
        # Individual IP results
        ip_results_table = Table(title="Individual IP Assessment", box=box.SIMPLE, border_style="blue")
        ip_results_table.add_column("IP Address", style="bold white")
        ip_results_table.add_column("Risk", justify="center")
        ip_results_table.add_column("Status", style="bold")
        ip_results_table.add_column("Key Findings", style="dim")
        
        for ip, (level, color) in threat_levels.items():
            # Handle both AnalysisResult objects and plain dictionaries
            result = results[ip]
            data = result.data if hasattr(result, 'data') else result
            findings = self._get_key_findings(data)
            
            # Create risk icon based on level
            if level == "HIGH RISK":
                icon = "!!!"
            elif level == "SUSPICIOUS":
                icon = "!?"
            else:
                icon = "OK"
                
            ip_results_table.add_row(ip, icon, f"[{color}]{level}[/{color}]", findings)
        
        self.console.print(summary_table)
        self.console.print(ip_results_table)
    
    def display_detailed_analysis(self, ip: str, results: Dict[str, Any]):
        """Display detailed analysis for a single IP"""
        # Header
        threat_score = self._calculate_threat_score(results)
        if threat_score >= 70:
            risk_color = "red"
            risk_level = "HIGH RISK"
        elif threat_score >= 30:
            risk_color = "yellow" 
            risk_level = "SUSPICIOUS"
        else:
            risk_color = "green"
            risk_level = "CLEAN"
        
        header_panel = Panel(
            f"[bold white]{ip}[/bold white]\n[{risk_color}]{risk_level}[/{risk_color}] (Threat Score: {threat_score}/100)",
            title=f"Detailed Analysis",
            border_style=risk_color
        )
        self.console.print(header_panel)
        
        # Create multi-column layout for different data sources
        columns = []
        
        # VirusTotal results
        if 'virustotal' in results:
            vt_data = results['virustotal']
            if vt_data.get('found'):
                vt_content = self._format_virustotal_results(vt_data)
                columns.append(Panel(vt_content, title="VirusTotal", border_style="purple"))
        
        # AbuseIPDB results  
        if 'abuseipdb' in results:
            abuse_data = results['abuseipdb']
            if abuse_data.get('found'):
                abuse_content = self._format_abuseipdb_results(abuse_data)
                columns.append(Panel(abuse_content, title="AbuseIPDB", border_style="red"))
        
        # GreyNoise results
        if 'greynoise' in results:
            gn_data = results['greynoise']
            if gn_data.get('found'):
                gn_content = self._format_greynoise_results(gn_data)
                columns.append(Panel(gn_content, title="GreyNoise", border_style="blue"))
        
        # ThreatFox results
        if 'threatfox' in results:
            tf_data = results['threatfox']
            if tf_data.get('found'):
                tf_content = self._format_threatfox_results(tf_data)
                columns.append(Panel(tf_content, title="ThreatFox", border_style="orange1"))
        
        # IPInfo results
        if 'ipinfo' in results:
            ip_data = results['ipinfo'] 
            if ip_data.get('found'):
                ip_content = self._format_ipinfo_results(ip_data)
                columns.append(Panel(ip_content, title="IPInfo", border_style="green"))
        
        if columns:
            self.console.print(Columns(columns, equal=True))
        else:
            self.console.print("[dim]No detailed results available[/dim]")
    
    def _calculate_threat_score(self, results: Dict[str, Any]) -> int:
        """Calculate composite threat score from all sources"""
        score = 0
        
        # VirusTotal scoring
        if 'virustotal' in results and results['virustotal'].get('found'):
            vt = results['virustotal']
            if vt['malicious'] > 0:
                score += min(50, vt['malicious'] * 5)  # Max 50 points
            if vt['suspicious'] > 0:
                score += min(20, vt['suspicious'] * 2)  # Max 20 points
        
        # AbuseIPDB scoring
        if 'abuseipdb' in results and results['abuseipdb'].get('found'):
            abuse = results['abuseipdb']
            score += min(30, int(abuse['confidence_score'] * 0.3))  # Max 30 points
        
        # GreyNoise scoring (malicious classification)
        if 'greynoise' in results and results['greynoise'].get('found'):
            gn = results['greynoise']
            if gn.get('malicious'):
                score += 25
            elif gn.get('classification') == 'suspicious':
                score += 15
        
        # ThreatFox scoring
        if 'threatfox' in results and results['threatfox'].get('found'):
            tf = results['threatfox']
            score += min(40, tf.get('ioc_count', 0) * 10)  # Max 40 points
        
        return min(100, score)
    
    def _get_key_findings(self, results: Dict[str, Any]) -> str:
        """Extract key findings for summary display"""
        findings = []
        
        # Check each source for key indicators
        if 'virustotal' in results and results['virustotal'].get('malicious', 0) > 0:
            findings.append(f"VT: {results['virustotal']['malicious']} detections")
        
        if 'abuseipdb' in results and results['abuseipdb'].get('confidence_score', 0) > 0:
            findings.append(f"Abuse: {results['abuseipdb']['confidence_score']}%")
        
        if 'greynoise' in results and results['greynoise'].get('malicious'):
            findings.append("GN: Malicious")
        
        if 'threatfox' in results and results['threatfox'].get('ioc_count', 0) > 0:
            findings.append(f"TF: {results['threatfox']['ioc_count']} IOCs")
        
        return ", ".join(findings) if findings else "No threats detected"
    
    def _format_virustotal_results(self, data: Dict[str, Any]) -> str:
        """Format VirusTotal results for display"""
        content = []
        content.append(f"[red]Malicious:[/red] {data.get('malicious', 0)}")
        content.append(f"[yellow]Suspicious:[/yellow] {data.get('suspicious', 0)}")
        content.append(f"[green]Harmless:[/green] {data.get('harmless', 0)}")
        content.append(f"[dim]Total Engines:[/dim] {data.get('total_engines', 0)}")
        
        if data.get('reputation'):
            content.append(f"[blue]Reputation:[/blue] {data['reputation']}")
        
        if data.get('malware_families'):
            content.append(f"[purple]Malware:[/purple] {', '.join(data['malware_families'][:3])}")
        
        return "\n".join(content)
    
    def _format_abuseipdb_results(self, data: Dict[str, Any]) -> str:
        """Format AbuseIPDB results for display"""
        content = []
        content.append(f"[red]Confidence:[/red] {data.get('confidence_score', 0)}%")
        content.append(f"[yellow]Reports:[/yellow] {data.get('total_reports', 0)}")
        
        if data.get('country_name'):
            content.append(f"[blue]Country:[/blue] {data['country_name']}")
        
        if data.get('isp'):
            content.append(f"[green]ISP:[/green] {data['isp'][:20]}...")
        
        if data.get('last_reported'):
            content.append(f"[dim]Last Report:[/dim] {data['last_reported'][:10]}")
        
        return "\n".join(content)
    
    def _format_greynoise_results(self, data: Dict[str, Any]) -> str:
        """Format GreyNoise results for display"""
        content = []
        
        classification = data.get('classification', 'unknown')
        if classification == 'malicious':
            content.append(f"[red]Status:[/red] {classification.upper()}")
        elif classification == 'benign':
            content.append(f"[green]Status:[/green] {classification.upper()}")
        else:
            content.append(f"[yellow]Status:[/yellow] {classification.upper()}")
        
        if data.get('actor'):
            content.append(f"[purple]Actor:[/purple] {data['actor']}")
        
        if data.get('tags'):
            content.append(f"[blue]Tags:[/blue] {', '.join(data['tags'][:2])}")
        
        if data.get('first_seen'):
            content.append(f"[dim]First Seen:[/dim] {data['first_seen'][:10]}")
        
        return "\n".join(content)
    
    def _format_threatfox_results(self, data: Dict[str, Any]) -> str:
        """Format ThreatFox results for display"""
        content = []
        content.append(f"[red]IOCs Found:[/red] {data.get('ioc_count', 0)}")
        
        if data.get('malware_families'):
            content.append(f"[purple]Malware:[/purple] {', '.join(data['malware_families'][:2])}")
        
        if data.get('threat_types'):
            content.append(f"[yellow]Threats:[/yellow] {', '.join(data['threat_types'][:2])}")
        
        if data.get('confidence_level'):
            content.append(f"[blue]Confidence:[/blue] {data['confidence_level']:.1f}%")
        
        return "\n".join(content)
    
    def _format_ipinfo_results(self, data: Dict[str, Any]) -> str:
        """Format IPInfo results for display"""
        content = []
        
        if data.get('country'):
            location = f"{data.get('city', 'Unknown')}, {data['country']}"
            content.append(f"[blue]Location:[/blue] {location}")
        
        if data.get('asn_name'):
            content.append(f"[green]ASN:[/green] {data['asn_name'][:25]}...")
        
        if data.get('organization'):
            content.append(f"[yellow]Org:[/yellow] {data['organization'][:25]}...")
        
        if data.get('privacy_vpn'):
            content.append(f"[red]VPN/Proxy:[/red] Detected")
        
        return "\n".join(content)