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
from ..utils.threat_scoring import ThreatScorer
from .dashboard import ThreatIntelligenceDashboard


class SOCInterface:
    """Advanced CLI interface for SOC analysts"""
    
    def __init__(self):
        self.console = Console(record=True)
        self.session_start = datetime.now()
        self.dashboard = ThreatIntelligenceDashboard(self.console)
        
    def display_banner(self, available_sources: list = None):
        """Display SOC Forge banner with system info"""
        banner_text = """===============================================================================
                              SOC FORGE v2.0
                        ADVANCED IP THREAT INTELLIGENCE
==============================================================================="""

        self.console.print(banner_text, style="bold blue")
        self.console.print(f"Session Start: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}")

        if available_sources:
            sources_text = " | ".join([source.replace('_', '').title() for source in available_sources])
            self.console.print(f"Enabled Sources: {sources_text}")

        self.console.print("-------------------------------------------------------------------------------")

    def display_main_menu(self) -> str:
        """Display the main menu with core SOC operations"""
        menu_text = """
Available Operations:

  [1] Threat Scan
      • Perform single or bulk lookup across all configured intelligence feeds

  [2] Generate SIEM / Kibana Queries
      • Convert indicators into ready-to-use KQL / Lucene / EQL / Splunk syntax

  [3] API Configuration & Health Check
      • Validate API keys, check rate limits, and verify feed connectivity

  [0] Exit

-------------------------------------------------------------------------------"""

        self.console.print(menu_text)
        return self.console.input("Select an option: ")

    def get_ip_input(self) -> str:
        """Get IP input from user with helpful guidance"""
        input_guidelines = """
INPUT GUIDELINES
  • Single IP:           8.8.8.8
  • Multiple (comma):    8.8.8.8, 1.1.1.1, 208.67.222.222
  • Line-separated:      One per line
  • With ports:          192.168.1.1:80, 10.0.0.1:443
  • With prefixes:       IP: 8.8.8.8, Address: 1.1.1.1

Press ENTER twice to submit, or Ctrl+C to cancel.
-------------------------------------------------------------------------------

Enter indicators:"""

        self.console.print(input_guidelines)

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
            self.console.print("\n[red]No valid public IPs found for analysis[/red]")

            if parsing_result.private_ips_found:
                self.console.print(f"Private IPs found: {len(parsing_result.private_ips_found)}")
                for ip in parsing_result.private_ips_found[:5]:
                    self.console.print(f"  • {ip}")
                if len(parsing_result.private_ips_found) > 5:
                    self.console.print(f"  ... and {len(parsing_result.private_ips_found) - 5} more")

            return False

        # Success parsing results
        results_text = f"""
-------------------------------------------------------------------------------
INPUT PARSING RESULTS
-------------------------------------------------------------------------------
  Valid Public IPs   : {len(parsing_result.valid_ips)}
  Private IPs Found  : {len(parsing_result.private_ips_found)}
  Invalid Entries    : {len(parsing_result.invalid_entries)}
  Duplicates Removed : {parsing_result.duplicates_removed}

-------------------------------------------------------------------------------
TARGETS FOR ANALYSIS
-------------------------------------------------------------------------------"""

        self.console.print(results_text)

        # IP list
        for i, ip in enumerate(parsing_result.valid_ips, 1):
            self.console.print(f"  {i:<3} {ip:<15} Public")

        return True

    def generate_siem_queries(self) -> None:
        """Generate SIEM/Kibana queries for indicators"""
        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("SIEM / KIBANA QUERY GENERATION")
        self.console.print("-------------------------------------------------------------------------------")

        # Get indicators input
        indicators_input = self.get_ip_input()
        if not indicators_input.strip():
            return

        # Parse indicators (reuse IP parser for now)
        from ..core.ip_parser import IPParser
        parser = IPParser()
        parsing_result = parser.extract_ips(indicators_input, include_private=True)

        if not parsing_result.valid_ips and not parsing_result.private_ips_found:
            self.console.print("[red]No valid indicators found[/red]")
            return

        all_ips = parsing_result.valid_ips + parsing_result.private_ips_found

        # Generate different query types
        query_types = {
            "Elasticsearch/Kibana KQL": self._generate_kibana_kql,
            "Splunk SPL": self._generate_splunk_spl,
            "Microsoft Sentinel KQL": self._generate_sentinel_kql,
            "Elastic EQL": self._generate_elastic_eql,
            "Generic Lucene": self._generate_lucene_query
        }

        for query_name, generator_func in query_types.items():
            self.console.print(f"\n[bold cyan]{query_name}:[/bold cyan]")
            queries = generator_func(all_ips)
            for query_type, query in queries.items():
                self.console.print(f"\n[yellow]{query_type}:[/yellow]")
                self.console.print(f"[green]{query}[/green]")

    def _generate_kibana_kql(self, ips: list) -> dict:
        """Generate Kibana KQL queries"""
        ip_list = " OR ".join(ips)
        return {
            "Source IP Match": f"source.ip: ({ip_list})",
            "Destination IP Match": f"destination.ip: ({ip_list})",
            "Any IP Field": f"*.ip: ({ip_list})",
            "Network Traffic": f"(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: network"
        }

    def _generate_splunk_spl(self, ips: list) -> dict:
        """Generate Splunk SPL queries"""
        ip_list = " OR ".join([f'"{ip}"' for ip in ips])
        return {
            "Source IP Search": f'src_ip IN ({ip_list})',
            "Destination IP Search": f'dest_ip IN ({ip_list})',
            "Any IP Field": f'src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}) OR ip IN ({ip_list})',
            "Stats by IP": f'src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}) | stats count by src_ip, dest_ip'
        }

    def _generate_sentinel_kql(self, ips: list) -> dict:
        """Generate Microsoft Sentinel KQL queries"""
        ip_list = '","'.join(ips)
        return {
            "Network Connections": f'CommonSecurityLog | where SourceIP in ("{ip_list}") or DestinationIP in ("{ip_list}")',
            "DNS Queries": f'DnsEvents | where ClientIP in ("{ip_list}") or ServerIP in ("{ip_list}")',
            "Security Events": f'SecurityEvent | where IpAddress in ("{ip_list}") or WorkstationIP in ("{ip_list}")',
            "Firewall Logs": f'AzureDiagnostics | where SourceIP in ("{ip_list}") or TargetIP in ("{ip_list}")'
        }

    def _generate_elastic_eql(self, ips: list) -> dict:
        """Generate Elastic EQL queries"""
        ip_conditions = " or ".join([f'source.ip == "{ip}" or destination.ip == "{ip}"' for ip in ips])
        ip_list = '","'.join(ips)
        return {
            "Network Events": f'network where {ip_conditions}',
            "Process Events": f'process where source.ip in ("{ip_list}") or destination.ip in ("{ip_list}")' if ips else "",
            "Sequence Detection": f'sequence by source.ip [network where destination.ip in ("{ip_list}")] [process where true]' if ips else ""
        }

    def _generate_lucene_query(self, ips: list) -> dict:
        """Generate generic Lucene queries"""
        ip_list = " OR ".join(ips)
        return {
            "Basic IP Match": f"ip:({ip_list})",
            "Source IP": f"src_ip:({ip_list})",
            "Destination IP": f"dst_ip:({ip_list})",
            "Any IP Field": f"*ip*:({ip_list})"
        }

    def display_api_health_check(self, analyzer) -> None:
        """Display API configuration and health check"""
        self.console.print("\n")
        self.console.print("-------------------------------------------------------------------------------")
        self.console.print("API CONFIGURATION & HEALTH CHECK")
        self.console.print("-------------------------------------------------------------------------------")

        if not analyzer:
            self.console.print("[red]No analyzer available[/red]")
            return

        # Check API status
        self.console.print("\nChecking APIs...")

        api_configs = {
            'virustotal': 'VirusTotal',
            'abuseipdb': 'AbuseIPDB',
            'ipinfo': 'IPInfo',
            'threatfox': 'ThreatFox',
            'greynoise': 'GreyNoise',
            'shodan': 'Shodan',
            'otx': 'AlienVault OTX'
        }

        available_clients = analyzer.clients.keys()

        for api_key, api_name in api_configs.items():
            if api_key in available_clients:
                # Try to test the API
                try:
                    # Simple connectivity test - this would need to be implemented in each client
                    status = "[green]OK[/green]"
                except Exception:
                    status = "[red]ERROR[/red]"
            else:
                status = "[yellow]NOT CONFIGURED[/yellow]"

            self.console.print(f"  • {api_name:<15} {status}")

        # Display configuration summary
        self.console.print(f"\n[bold]Configuration Summary:[/bold]")
        self.console.print(f"  Active APIs: {len(available_clients)}/{len(api_configs)}")
        self.console.print(f"  Available Sources: {', '.join([name.title() for name in available_clients])}")

    def run_dashboard_analysis(self, ips: list, analyzer) -> None:
        """Run comprehensive analysis and display dashboard directly"""
        available_sources = list(analyzer.clients.keys())
        self.display_analysis_progress(ips, available_sources)

        results = analyzer.analyze_multiple_ips(ips)

        # Display full dashboard for each IP
        for ip in ips:
            if ip in results:
                self.display_threat_intelligence_dashboard(ip, results[ip].data)
    
    def display_analysis_progress(self, ips: List[str], sources: List[str]):
        """Display real-time analysis progress"""
        total_operations = len(ips) * len(sources)

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console,
            transient=False
        ) as progress:

            main_task = progress.add_task("Analysis Status:", total=total_operations)

            for ip in ips:
                for source in sources:
                    progress.update(main_task, advance=1)
                    time.sleep(0.1)  # Simulate API calls

            progress.update(main_task, description="Analysis Status:")
            time.sleep(0.3)

        self.console.print("-------------------------------------------------------------------------------")
    
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
            threat_score = ThreatScorer.calculate_ip_threat_score(data)

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
            findings = ThreatScorer.extract_key_findings(data)
            
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
        threat_score = ThreatScorer.calculate_ip_threat_score(results)
        risk_level = ThreatScorer.get_threat_level(threat_score)
        risk_color = ThreatScorer.get_threat_color(threat_score)
        
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

                # Show detailed vendor breakdown if there are detections
                if vt_data.get('engines_detected'):
                    self.console.print()
                    self.display_virustotal_vendor_breakdown(ip, vt_data)
        
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

        # Shodan results
        if 'shodan' in results:
            shodan_data = results['shodan']
            if shodan_data.get('found'):
                shodan_content = self._format_shodan_results(shodan_data)
                columns.append(Panel(shodan_content, title="Shodan", border_style="cyan"))

        if columns:
            self.console.print(Columns(columns, equal=True))
        else:
            self.console.print("[dim]No detailed results available[/dim]")
    
    
    def _format_virustotal_results(self, data: Dict[str, Any]) -> str:
        """Format VirusTotal results for display"""
        content = []

        # Detection summary
        ratio = data.get('vendor_detection_ratio', '0/0')
        content.append(f"[bold red]Detection Ratio:[/bold red] {ratio}")
        content.append(f"[red]Malicious:[/red] {data.get('malicious', 0)}")
        content.append(f"[yellow]Suspicious:[/yellow] {data.get('suspicious', 0)}")
        content.append(f"[green]Harmless:[/green] {data.get('harmless', 0)}")

        if data.get('reputation'):
            content.append(f"[blue]Reputation:[/blue] {data['reputation']}")

        # Show top detecting engines
        engines_detected = data.get('engines_detected', [])
        if engines_detected:
            content.append(f"\n[bold]Top Detections:[/bold]")
            for i, engine in enumerate(engines_detected[:5]):  # Show top 5
                result = engine.get('result', 'N/A')
                category = engine.get('category', 'unknown')
                color = "red" if category == "malicious" else "yellow"
                content.append(f"[{color}]• {engine['engine']}:[/{color}] {result}")

        if data.get('malware_families'):
            content.append(f"\n[purple]Malware Families:[/purple] {', '.join(data['malware_families'][:3])}")

        return "\n".join(content)

    def display_virustotal_vendor_breakdown(self, ip: str, vt_data: Dict[str, Any]):
        """Display detailed VirusTotal vendor breakdown in a table"""
        if not vt_data.get('engines_detected'):
            return

        # Create detailed vendor table
        vendor_table = Table(title=f"VirusTotal Vendor Detections - {ip}",
                           box=box.SIMPLE, border_style="red")
        vendor_table.add_column("Engine", style="bold white", width=20)
        vendor_table.add_column("Result", style="red", width=30)
        vendor_table.add_column("Category", justify="center", width=12)
        vendor_table.add_column("Method", style="dim", width=15)

        for engine in vt_data['engines_detected']:
            category = engine.get('category', 'unknown')
            category_color = "red" if category == "malicious" else "yellow"

            vendor_table.add_row(
                engine.get('engine', 'Unknown'),
                engine.get('result', 'N/A'),
                f"[{category_color}]{category.upper()}[/{category_color}]",
                engine.get('method', 'N/A')
            )

        self.console.print(vendor_table)

        # Additional statistics
        stats_panel = Panel(
            f"[bold]Detection Statistics:[/bold]\n"
            f"Detection Ratio: [red]{vt_data.get('vendor_detection_ratio', '0/0')}[/red]\n"
            f"Reputation Score: [blue]{vt_data.get('reputation', 'N/A')}[/blue]\n"
            f"Last Analysis: [dim]{vt_data.get('last_analysis_date', 'N/A')}[/dim]",
            title="VirusTotal Summary",
            border_style="purple"
        )
        self.console.print(stats_panel)

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

    def _format_shodan_results(self, data: Dict[str, Any]) -> str:
        """Format Shodan results for display"""
        content = []

        # Basic info
        services_count = len(data.get('services', []))
        content.append(f"[blue]Open Ports:[/blue] {len(data.get('ports', []))}")
        content.append(f"[green]Services:[/green] {services_count}")

        # Vulnerabilities
        vuln_count = len(data.get('vulnerabilities', []))
        if vuln_count > 0:
            content.append(f"[red]Vulnerabilities:[/red] {vuln_count}")

        # Operating system
        if data.get('operating_system'):
            content.append(f"[yellow]OS:[/yellow] {data['operating_system']}")

        # Organization
        if data.get('organization'):
            org = data['organization'][:25] + "..." if len(data.get('organization', '')) > 25 else data['organization']
            content.append(f"[cyan]Org:[/cyan] {org}")

        # Top services
        services = data.get('services', [])
        if services:
            content.append(f"\n[bold]Top Services:[/bold]")
            for service in services[:3]:  # Show top 3
                port = service.get('port', '')
                product = service.get('product', 'Unknown')[:20]
                content.append(f"[dim]• Port {port}:[/dim] {product}")

        # Hostnames
        hostnames = data.get('hostnames', [])
        if hostnames:
            hostname_list = ', '.join(hostnames[:2])
            content.append(f"\n[purple]Hostnames:[/purple] {hostname_list}")

        # Tags
        tags = data.get('tags', [])
        if tags:
            tag_list = ', '.join(tags[:3])
            content.append(f"\n[orange1]Tags:[/orange1] {tag_list}")

        return "\n".join(content)

    def display_threat_intelligence_dashboard(self, ip: str, analysis_results: Dict[str, Any]) -> None:
        """Display the comprehensive threat intelligence dashboard"""
        self.dashboard.display_threat_intelligence_dashboard(ip, analysis_results)

    def display_quick_threat_dashboard(self, ip: str, quick_results: Dict[str, Any]) -> None:
        """Display the quick threat assessment dashboard"""
        self.dashboard.display_quick_dashboard(ip, quick_results)