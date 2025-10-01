"""
Threat Intelligence Dashboard
Advanced UI component for displaying threat intelligence data in a comprehensive format
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich import box
from typing import Dict, Any, List, Optional
from datetime import datetime
import time

from ..utils.threat_scoring import ThreatScorer


class ThreatIntelligenceDashboard:
    """Advanced threat intelligence dashboard for comprehensive IP analysis display"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console(record=True)

    def display_threat_intelligence_dashboard(self, ip: str, analysis_results: Dict[str, Any]) -> None:
        """
        Display comprehensive threat intelligence dashboard for an IP

        Args:
            ip: IP address being analyzed
            analysis_results: Complete analysis results from all sources
        """
        # Clear screen and prepare dashboard
        self.console.clear()

        # Display main header
        self._display_header(ip, analysis_results)

        # Display reputation summary
        self._display_reputation_summary(analysis_results)

        # Display geographic and network information
        self._display_geographic_network_info(analysis_results)

        # Display open ports and services (Shodan-like info)
        self._display_open_ports_services(analysis_results)

        # Display VirusTotal key vendor analysis
        self._display_virustotal_vendor_analysis(analysis_results)

        # Display AlienVault OTX threat pulses
        self._display_otx_threat_pulses(analysis_results)

        # Display recent report tags
        self._display_recent_report_tags(analysis_results)

        # Display references and URLs
        self._display_references_urls(ip)

        # Display raw feed access commands
        self._display_raw_feed_access(ip)

        # Footer
        self._display_footer()

    def _display_header(self, ip: str, analysis_results: Dict[str, Any]) -> None:
        """Display the main dashboard header"""
        header_text = "=" * 80 + "\n"
        header_text += " " * 25 + "THREAT INTELLIGENCE DASHBOARD\n"
        header_text += "=" * 80 + "\n"

        # Get IP type (determine from context)
        ip_type = "IP"  # Could be enhanced to detect domain, hash, etc.

        # Current time
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        header_text += f"Indicator: {ip:<30} Type: {ip_type}\n"
        header_text += f"Lookup Time: {current_time}\n"

        self.console.print(Text(header_text, style="bold white"))

    def _display_reputation_summary(self, analysis_results: Dict[str, Any]) -> None:
        """Display reputation summary from all feeds"""
        self.console.print("\n" + "-" * 80)
        self.console.print("REPUTATION SUMMARY")
        self.console.print("-" * 80)

        # Create reputation table
        reputation_table = Table(box=box.SIMPLE, padding=(0, 1))
        reputation_table.add_column("Feed", style="bold white", width=12)
        reputation_table.add_column("Verdict", width=12)
        reputation_table.add_column("Confidence", width=10, justify="center")
        reputation_table.add_column("Last Seen", width=20)

        # VirusTotal
        vt_data = analysis_results.get('virustotal', {})
        if vt_data.get('found'):
            malicious_count = vt_data.get('malicious', 0)
            total_engines = vt_data.get('total_engines', 0)
            if malicious_count > 0:
                verdict = "[red]Malicious[/red]"
                confidence = min(85, int((malicious_count / total_engines) * 100)) if total_engines > 0 else 0
            else:
                verdict = "[green]Clean[/green]"
                confidence = 95
            last_seen_raw = vt_data.get('last_analysis_date', '')
            if last_seen_raw and isinstance(last_seen_raw, str):
                last_seen = last_seen_raw.split('T')[0]
            elif last_seen_raw and isinstance(last_seen_raw, int):
                # Convert timestamp to date string
                last_seen = datetime.fromtimestamp(last_seen_raw).strftime('%Y-%m-%d')
            else:
                last_seen = '--'
        else:
            verdict, confidence, last_seen = "[dim]Unknown[/dim]", "--", "--"

        reputation_table.add_row("VirusTotal", verdict, str(confidence) if confidence != "--" else confidence, last_seen)

        # AbuseIPDB
        abuse_data = analysis_results.get('abuseipdb', {})
        if abuse_data.get('found'):
            confidence_score = abuse_data.get('confidence_score', 0)
            if confidence_score >= 75:
                verdict = "[red]Malicious[/red]"
            elif confidence_score >= 25:
                verdict = "[yellow]Suspicious[/yellow]"
            else:
                verdict = "[green]Clean[/green]"
            last_reported_raw = abuse_data.get('last_reported', '')
            if last_reported_raw and isinstance(last_reported_raw, str):
                last_seen = last_reported_raw.split('T')[0]
            elif last_reported_raw and isinstance(last_reported_raw, int):
                # Convert timestamp to date string
                last_seen = datetime.fromtimestamp(last_reported_raw).strftime('%Y-%m-%d')
            else:
                last_seen = '--'
        else:
            verdict, confidence_score, last_seen = "[dim]Unknown[/dim]", "--", "--"

        reputation_table.add_row("AbuseIPDB", verdict, str(confidence_score) if confidence_score != "--" else confidence_score, last_seen)

        # GreyNoise
        gn_data = analysis_results.get('greynoise', {})
        if gn_data.get('found'):
            classification = gn_data.get('classification', 'unknown')
            if classification == 'malicious':
                verdict = "[red]Malicious[/red]"
                confidence = 90
            elif classification == 'benign':
                verdict = "[green]Noise[/green]"
                confidence = 40
            else:
                verdict = "[yellow]Unknown[/yellow]"
                confidence = 30
            last_seen_raw = gn_data.get('last_seen', '')
            if last_seen_raw and isinstance(last_seen_raw, str):
                last_seen = last_seen_raw.split('T')[0]
            elif last_seen_raw and isinstance(last_seen_raw, int):
                # Convert timestamp to date string
                last_seen = datetime.fromtimestamp(last_seen_raw).strftime('%Y-%m-%d')
            else:
                last_seen = '--'
        else:
            verdict, confidence, last_seen = "[dim]Unknown[/dim]", "--", "--"

        reputation_table.add_row("GreyNoise", verdict, str(confidence) if confidence != "--" else confidence, last_seen)

        # ThreatFox
        tf_data = analysis_results.get('threatfox', {})
        if tf_data.get('found'):
            ioc_count = tf_data.get('ioc_count', 0)
            if ioc_count > 0:
                verdict = "[red]Malicious[/red]"
                confidence = min(90, 60 + (ioc_count * 10))
            else:
                verdict = "[green]Clean[/green]"
                confidence = 85
            last_seen = '--'  # ThreatFox doesn't provide specific last seen
        else:
            verdict, confidence, last_seen = "[dim]Unknown[/dim]", "--", "--"

        reputation_table.add_row("ThreatFox", verdict, str(confidence) if confidence != "--" else confidence, last_seen)

        # Shodan
        shodan_data = analysis_results.get('shodan', {})
        if shodan_data.get('found'):
            # Determine verdict based on services and vulnerabilities
            services_count = len(shodan_data.get('services', []))
            vuln_count = len(shodan_data.get('vulnerabilities', []))

            if vuln_count > 0:
                verdict = "[red]Vulnerable[/red]"
                confidence = min(90, 50 + (vuln_count * 10))
            elif services_count > 5:
                verdict = "[yellow]Exposed[/yellow]"
                confidence = min(70, 30 + (services_count * 5))
            else:
                verdict = "[green]Monitored[/green]"
                confidence = 60

            last_seen_raw = shodan_data.get('last_update', '')
            if last_seen_raw and isinstance(last_seen_raw, str):
                last_seen = last_seen_raw.split('T')[0]
            else:
                last_seen = '--'
        else:
            verdict, confidence, last_seen = "[dim]Unknown[/dim]", "--", "--"

        reputation_table.add_row("Shodan", verdict, str(confidence) if confidence != "--" else confidence, last_seen)

        # AlienVault OTX
        otx_data = analysis_results.get('otx', {})
        if otx_data.get('found'):
            pulse_count = otx_data.get('pulse_count', 0)
            threat_score = otx_data.get('threat_score', 0)
            av_detections = len(otx_data.get('av_detections', []))
            malware_count = otx_data.get('malware_count', 0)

            # Determine verdict based on all factors
            if pulse_count > 5 or threat_score > 70 or av_detections > 5:
                verdict = "[red]Malicious[/red]"
                confidence = min(95, 60 + max(pulse_count * 5, av_detections * 3))
            elif pulse_count > 0 or threat_score > 30 or av_detections > 0 or malware_count > 0:
                verdict = "[yellow]Suspicious[/yellow]"
                confidence = min(80, 40 + max(pulse_count * 5, av_detections * 3))
            else:
                # No threats found
                verdict = "[green]Clean[/green]"
                confidence = 85

            # Get most recent pulse date
            pulses = otx_data.get('pulses', [])
            if pulses:
                last_seen_raw = pulses[0].get('modified', pulses[0].get('created', ''))
                if last_seen_raw and isinstance(last_seen_raw, str):
                    last_seen = last_seen_raw.split('T')[0]
                else:
                    last_seen = '--'
            else:
                last_seen = '--'
        else:
            verdict, confidence, last_seen = "[dim]Unknown[/dim]", "--", "--"

        reputation_table.add_row("AlienVault", verdict, str(confidence) if confidence != "--" else confidence, last_seen)

        self.console.print(reputation_table)

    def _display_geographic_network_info(self, analysis_results: Dict[str, Any]) -> None:
        """Display geographic and network information"""
        self.console.print("\n" + "-" * 80)
        self.console.print("GEOGRAPHIC & NETWORK INFORMATION")
        self.console.print("-" * 80)

        geo_table = Table(box=box.SIMPLE, padding=(0, 1))
        geo_table.add_column("Field", style="bold white", width=12)
        geo_table.add_column("Value", width=30)

        # Get geographic info from IPInfo or VirusTotal
        ipinfo_data = analysis_results.get('ipinfo', {})
        vt_data = analysis_results.get('virustotal', {})

        # Country
        country = "Unknown"
        if ipinfo_data.get('found') and ipinfo_data.get('country'):
            country = ipinfo_data['country']
        elif vt_data.get('found') and vt_data.get('country'):
            country = vt_data['country']
        geo_table.add_row("Country", country)

        # City
        city = "Unknown"
        if ipinfo_data.get('found') and ipinfo_data.get('city'):
            city = ipinfo_data['city']
        geo_table.add_row("City", city)

        # ASN / Organization
        asn_org = "Unknown"
        if ipinfo_data.get('found'):
            if ipinfo_data.get('asn_name'):
                asn_org = f"AS{ipinfo_data.get('asn', '')} - {ipinfo_data['asn_name']}"
            elif ipinfo_data.get('organization'):
                asn_org = ipinfo_data['organization']
        elif vt_data.get('found'):
            if vt_data.get('as_owner'):
                asn_org = f"AS{vt_data.get('asn', '')} - {vt_data['as_owner']}"
        geo_table.add_row("ASN / Org", asn_org)

        # ISP
        isp = "Unknown"
        if ipinfo_data.get('found') and ipinfo_data.get('organization'):
            isp = ipinfo_data['organization']
        geo_table.add_row("ISP", isp)

        self.console.print(geo_table)

    def _display_open_ports_services(self, analysis_results: Dict[str, Any]) -> None:
        """Display open ports and services (Shodan information)"""
        self.console.print("\n" + "-" * 80)
        self.console.print("OPEN PORTS & SERVICES (Shodan)")
        self.console.print("-" * 80)

        ports_table = Table(box=box.SIMPLE, padding=(0, 1))
        ports_table.add_column("Port", width=8, justify="right")
        ports_table.add_column("Protocol", width=8)
        ports_table.add_column("Service", width=12)
        ports_table.add_column("Product", width=25)
        ports_table.add_column("Version", width=12)

        # Check if Shodan data is available
        shodan_data = analysis_results.get('shodan', {})
        if shodan_data.get('found') and shodan_data.get('services'):
            # Use actual Shodan data
            for service in shodan_data['services'][:10]:  # Show up to 10 services
                port = str(service.get('port', ''))
                protocol = service.get('protocol', 'tcp').upper()
                service_name = service.get('service', 'unknown')
                product = service.get('product', '')[:25]  # Truncate long product names
                version = service.get('version', '')[:12]  # Truncate long versions

                ports_table.add_row(port, protocol, service_name, product, version)
        else:
            # Show message when no Shodan data is available
            if shodan_data.get('found') == False:
                ports_table.add_row("--", "--", "No services detected", "--", "--")
            else:
                ports_table.add_row("--", "--", "Shodan data unavailable", "--", "--")

        self.console.print(ports_table)

        # Show additional Shodan information if available
        if shodan_data.get('found'):
            additional_info = []

            if shodan_data.get('operating_system'):
                additional_info.append(f"OS: {shodan_data['operating_system']}")

            if shodan_data.get('hostnames'):
                hostnames = ', '.join(shodan_data['hostnames'][:3])  # Show first 3
                additional_info.append(f"Hostnames: {hostnames}")

            if shodan_data.get('vulnerabilities'):
                vuln_count = len(shodan_data['vulnerabilities'])
                additional_info.append(f"Vulnerabilities: {vuln_count} detected")

            if shodan_data.get('tags'):
                tags = ', '.join(shodan_data['tags'][:5])  # Show first 5 tags
                additional_info.append(f"Tags: {tags}")

            if additional_info:
                self.console.print(f"\nAdditional Info: {' | '.join(additional_info)}")

            # Display detailed service banners if available
            if shodan_data.get('services'):
                self._display_service_banners(shodan_data['services'])

            # Display vulnerability details if available
            if shodan_data.get('vulnerabilities') and len(shodan_data['vulnerabilities']) > 0:
                self._display_vulnerabilities(shodan_data['vulnerabilities'])

            # Display organization and network details
            self._display_shodan_network_details(shodan_data)

    def _display_service_banners(self, services: List[Dict[str, Any]]) -> None:
        """Display detailed service banners from Shodan"""
        self.console.print("\n[bold]Service Banners:[/bold]")

        banners_shown = 0
        # Show up to 8 services with banners
        for service in services[:15]:  # Check more services
            banner = service.get('banner', '').strip()
            if banner and banners_shown < 8:
                banners_shown += 1
                port = service.get('port', 'Unknown')
                product = service.get('product', 'Unknown Service')
                protocol = service.get('protocol', 'tcp').upper()
                ssl_enabled = service.get('ssl', False)

                # Truncate very long banners but allow more content
                if len(banner) > 400:
                    banner = banner[:400] + "\n... [truncated]"

                # Add SSL indicator
                ssl_indicator = " [SSL/TLS]" if ssl_enabled else ""

                # Create banner panel with more info
                banner_text = f"[cyan]Port {port}/{protocol}{ssl_indicator}[/cyan] - {product}\n[dim]{banner}[/dim]"
                banner_panel = Panel(banner_text, title=f"Banner #{banners_shown}", border_style="blue", expand=False)
                self.console.print(banner_panel)

        if banners_shown == 0:
            self.console.print("[dim]No banner data available[/dim]")

    def _display_vulnerabilities(self, vulnerabilities: List[str]) -> None:
        """Display vulnerability details from Shodan"""
        self.console.print("\n[bold red]Detected Vulnerabilities:[/bold red]")

        vuln_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True)
        vuln_table.add_column("CVE ID", style="bold red", width=20)
        vuln_table.add_column("Reference", width=55)

        # Show up to 25 vulnerabilities for better visibility
        display_limit = 25
        for vuln in vulnerabilities[:display_limit]:
            cve_id = vuln if isinstance(vuln, str) else str(vuln)
            reference = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            vuln_table.add_row(cve_id, reference)

        self.console.print(vuln_table)

        if len(vulnerabilities) > display_limit:
            remaining = len(vulnerabilities) - display_limit
            self.console.print(f"[dim]... and {remaining} more vulnerabilities[/dim]")

        # Add summary statistics
        self.console.print(f"\n[bold]Total Vulnerabilities Detected:[/bold] [red]{len(vulnerabilities)}[/red]")

    def _display_shodan_network_details(self, shodan_data: Dict[str, Any]) -> None:
        """Display additional Shodan network and organization details"""
        self.console.print("\n[bold]Network & Organization Details:[/bold]")

        details_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=False)
        details_table.add_column("Field", style="bold white", width=20)
        details_table.add_column("Value", width=55)

        if shodan_data.get('organization'):
            details_table.add_row("Organization", shodan_data['organization'])

        if shodan_data.get('isp'):
            details_table.add_row("ISP", shodan_data['isp'])

        if shodan_data.get('asn'):
            details_table.add_row("ASN", shodan_data['asn'])

        if shodan_data.get('country_name'):
            location_parts = [shodan_data.get('city', ''), shodan_data.get('region_code', ''), shodan_data.get('country_name', '')]
            location = ', '.join([p for p in location_parts if p])
            details_table.add_row("Location", location)

        if shodan_data.get('postal_code'):
            details_table.add_row("Postal Code", shodan_data['postal_code'])

        if shodan_data.get('latitude') and shodan_data.get('longitude'):
            coordinates = f"{shodan_data['latitude']}, {shodan_data['longitude']}"
            details_table.add_row("Coordinates", coordinates)

        if shodan_data.get('last_update'):
            details_table.add_row("Last Updated", shodan_data['last_update'])

        # Only print if we have data
        if details_table.row_count > 0:
            self.console.print(details_table)

    def _display_virustotal_vendor_analysis(self, analysis_results: Dict[str, Any]) -> None:
        """Display VirusTotal key vendor analysis"""
        self.console.print("\n" + "-" * 80)
        self.console.print("VIRUSTOTAL - KEY VENDOR ANALYSIS")
        self.console.print("-" * 80)

        vt_data = analysis_results.get('virustotal', {})
        if not vt_data.get('found'):
            self.console.print("[dim]No VirusTotal data available[/dim]")
            return

        vendor_table = Table(box=box.SIMPLE, padding=(0, 1))
        vendor_table.add_column("Vendor", style="bold white", width=12)
        vendor_table.add_column("Category", width=10)
        vendor_table.add_column("Signature / Result", width=35)

        # Get detection engines
        engines_detected = vt_data.get('engines_detected', [])
        engines_clean = vt_data.get('engines_clean', [])

        # Show key detections
        key_vendors = ['Fortinet', 'Kaspersky', 'Sophos', 'Microsoft', 'TrendMicro']

        for vendor in key_vendors:
            found = False

            # Check in detected engines
            for engine in engines_detected:
                if vendor.lower() in engine.get('engine', '').lower():
                    category = engine.get('category', 'Unknown')
                    result = engine.get('result', 'Unknown')

                    if category == 'malicious':
                        category_display = "[red]Malicious[/red]"
                    elif category == 'suspicious':
                        category_display = "[yellow]Suspicious[/yellow]"
                    else:
                        category_display = category.title()

                    vendor_table.add_row(vendor, category_display, result)
                    found = True
                    break

            # Check in clean engines if not found in detected
            if not found:
                for engine in engines_clean[:5]:  # Limit clean engines shown
                    if vendor.lower() in engine.get('engine', '').lower():
                        vendor_table.add_row(vendor, "[green]Clean[/green]", "No Threats Detected")
                        found = True
                        break

            # If still not found, show unknown
            if not found:
                vendor_table.add_row(vendor, "[dim]Unknown[/dim]", "--")

        self.console.print(vendor_table)

    def _display_otx_threat_pulses(self, analysis_results: Dict[str, Any]) -> None:
        """Display AlienVault OTX threat pulse information"""
        self.console.print("\n" + "-" * 80)
        self.console.print("ALIENVAULT OTX - THREAT INTELLIGENCE")
        self.console.print("-" * 80)

        otx_data = analysis_results.get('otx', {})
        if not otx_data.get('found'):
            self.console.print("[dim]No AlienVault OTX data available[/dim]")
            return

        pulse_count = otx_data.get('pulse_count', 0)
        threat_score = otx_data.get('threat_score', 0)

        # If no pulses, show available data
        if pulse_count == 0:
            self.console.print("[green]No threat pulses found for this IP[/green]")

            # Show threat indicators even without pulses
            threat_indicators = []

            passive_dns_count = otx_data.get('passive_dns_count', 0)
            if passive_dns_count > 0:
                threat_indicators.append(f"[yellow]Passive DNS: {passive_dns_count} domains[/yellow]")

            malware_count = otx_data.get('malware_count', 0)
            if malware_count > 0:
                threat_indicators.append(f"[red]Malware Samples: {malware_count}[/red]")

            url_count = otx_data.get('url_count', 0)
            if url_count > 0:
                threat_indicators.append(f"[orange1]URLs: {url_count}[/orange1]")

            av_detections = otx_data.get('av_detections', [])
            if av_detections:
                threat_indicators.append(f"[red]AV Detections: {len(av_detections)}[/red]")

            if threat_indicators:
                self.console.print("\n[bold]Threat Indicators:[/bold]")
                for indicator in threat_indicators:
                    self.console.print(f"  • {indicator}")

                # Show AV detections if present
                if av_detections:
                    self.console.print(f"\n[bold red]Antivirus Detections:[/bold red]")
                    for detection in av_detections[:10]:  # Show first 10
                        self.console.print(f"  • {detection}")
                    if len(av_detections) > 10:
                        self.console.print(f"  [dim]... and {len(av_detections) - 10} more[/dim]")

            # Show geographic data if available
            geo_info = []
            if otx_data.get('country'):
                geo_info.append(f"Country: {otx_data['country']}")
            if otx_data.get('city'):
                geo_info.append(f"City: {otx_data['city']}")
            if otx_data.get('asn'):
                geo_info.append(f"ASN: {otx_data['asn']}")

            if geo_info:
                self.console.print(f"\n[dim]Geographic Info: {' | '.join(geo_info)}[/dim]")

            return

        # Summary information
        summary_info = f"[bold]Pulses Found:[/bold] {pulse_count} | [bold]Threat Score:[/bold] "
        if threat_score > 70:
            summary_info += f"[red]{threat_score}[/red]"
        elif threat_score > 30:
            summary_info += f"[yellow]{threat_score}[/yellow]"
        else:
            summary_info += f"[green]{threat_score}[/green]"

        self.console.print(summary_info)

        # Display malware families if any
        malware_families = otx_data.get('malware_families', [])
        if malware_families:
            self.console.print(f"[bold red]Malware Families:[/bold red] {', '.join(malware_families[:10])}")

        # Display MITRE ATT&CK IDs if any
        attack_ids = otx_data.get('attack_ids', [])
        if attack_ids:
            self.console.print(f"[bold orange1]MITRE ATT&CK:[/bold orange1] {', '.join(attack_ids[:10])}")

        # Display targeted industries if any
        industries = otx_data.get('industries', [])
        if industries:
            self.console.print(f"[bold cyan]Targeted Industries:[/bold cyan] {', '.join(industries[:10])}")

        # Display individual pulses
        pulses = otx_data.get('pulses', [])
        if pulses:
            self.console.print("\n[bold]Recent Threat Pulses:[/bold]")

            pulse_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True)
            pulse_table.add_column("Date", style="dim", width=12)
            pulse_table.add_column("Pulse Name", style="bold white", width=35)
            pulse_table.add_column("Author", width=15)
            pulse_table.add_column("TLP", width=8)

            for pulse in pulses[:8]:  # Show up to 8 pulses
                date = pulse.get('created', '')[:10] if pulse.get('created') else '--'
                name = pulse.get('name', 'Unknown')[:35]
                author = pulse.get('author', 'Unknown')[:15]
                tlp = pulse.get('tlp', 'white').upper()

                # Color code TLP
                if tlp == "RED":
                    tlp_display = f"[red]{tlp}[/red]"
                elif tlp == "AMBER":
                    tlp_display = f"[yellow]{tlp}[/yellow]"
                elif tlp == "GREEN":
                    tlp_display = f"[green]{tlp}[/green]"
                else:
                    tlp_display = f"[dim]{tlp}[/dim]"

                pulse_table.add_row(date, name, author, tlp_display)

            self.console.print(pulse_table)

            # Show tags from pulses
            tags = otx_data.get('tags', [])
            if tags:
                self.console.print(f"\n[bold]Associated Tags:[/bold] {', '.join(tags[:15])}")

    def _display_recent_report_tags(self, analysis_results: Dict[str, Any]) -> None:
        """Display recent report tags from all sources"""
        self.console.print("\n" + "-" * 80)
        self.console.print("AGGREGATED THREAT TAGS")
        self.console.print("-" * 80)

        # Collect tags from different sources
        tags = set()

        # AlienVault OTX tags
        otx_data = analysis_results.get('otx', {})
        if otx_data.get('found') and otx_data.get('tags'):
            tags.update(otx_data['tags'])

        # GreyNoise tags
        gn_data = analysis_results.get('greynoise', {})
        if gn_data.get('found') and gn_data.get('tags'):
            tags.update(gn_data['tags'])

        # ThreatFox threat types as tags
        tf_data = analysis_results.get('threatfox', {})
        if tf_data.get('found'):
            if tf_data.get('threat_types'):
                tags.update(tf_data['threat_types'])
            if tf_data.get('malware_families'):
                tags.update([f"{family}" for family in tf_data['malware_families'][:5]])  # Limit malware families

        # VirusTotal categories as tags
        vt_data = analysis_results.get('virustotal', {})
        if vt_data.get('found') and vt_data.get('categories'):
            tags.update(vt_data['categories'])

        # Shodan tags
        shodan_data = analysis_results.get('shodan', {})
        if shodan_data.get('found') and shodan_data.get('tags'):
            tags.update(shodan_data['tags'])

        # AbuseIPDB report categories as tags
        abuse_data = analysis_results.get('abuseipdb', {})
        if abuse_data.get('found') and abuse_data.get('reports'):
            for report in abuse_data['reports'][:10]:  # Check first 10 reports
                if report.get('categories'):
                    # Map category IDs to names
                    category_names = self._map_abuseipdb_categories(report['categories'])
                    tags.update(category_names)

        # Display tags or message if none found
        if tags:
            # Remove empty strings and sort
            tags = sorted([t for t in tags if t and len(t) > 0])[:20]  # Limit to 20 tags
            tags_text = ", ".join(tags)
            self.console.print(tags_text)
        else:
            self.console.print("[dim]No threat tags available from any source[/dim]")

    def _map_abuseipdb_categories(self, category_ids: list) -> set:
        """Map AbuseIPDB category IDs to human-readable names"""
        category_map = {
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }

        names = set()
        for cat_id in category_ids:
            if cat_id in category_map:
                names.add(category_map[cat_id])
        return names

    def _display_references_urls(self, ip: str) -> None:
        """Display reference URLs for manual verification"""
        self.console.print("\n" + "-" * 80)
        self.console.print("REFERENCES / URL CHECKUPS")
        self.console.print("-" * 80)

        refs_table = Table(box=box.SIMPLE, padding=(0, 1))
        refs_table.add_column("Service", style="bold white", width=20)
        refs_table.add_column("URL", width=50)

        refs_table.add_row("VirusTotal Report:", f"https://www.virustotal.com/gui/ip-address/{ip}")
        refs_table.add_row("AbuseIPDB:", f"https://www.abuseipdb.com/check/{ip}")
        refs_table.add_row("Shodan:", f"https://www.shodan.io/host/{ip}")
        refs_table.add_row("AlienVault OTX:", f"https://otx.alienvault.com/indicator/ip/{ip}")
        refs_table.add_row("ThreatFox:", f"https://threatfox.abuse.ch/browse/indicator/{ip}")
        refs_table.add_row("GreyNoise:", f"https://www.greynoise.io/indicator/{ip}")

        self.console.print(refs_table)

    def _display_raw_feed_access(self, ip: str) -> None:
        """Display commands for raw feed access"""
        self.console.print("\n" + "-" * 80)
        self.console.print("RAW FEED ACCESS")
        self.console.print("-" * 80)

        raw_table = Table(box=box.SIMPLE, padding=(0, 1))
        raw_table.add_column("Command", style="bold white", width=20)
        raw_table.add_column("Description", width=50)

        raw_table.add_row("View full payloads:", f"threatctl lookup {ip} --raw")
        raw_table.add_row("Export JSON:", f"threatctl lookup {ip} --format json")

        self.console.print(raw_table)

    def _display_footer(self) -> None:
        """Display dashboard footer"""
        footer_text = "=" * 80
        self.console.print(f"\n{footer_text}")

    def display_quick_dashboard(self, ip: str, quick_results: Dict[str, Any]) -> None:
        """
        Display a simplified dashboard for quick assessments

        Args:
            ip: IP address being analyzed
            quick_results: Quick analysis results
        """
        self.console.print(f"\n[bold cyan]Quick Threat Assessment - {ip}[/bold cyan]")

        # Display basic threat info
        threat_level = quick_results.get('threat_level', 'UNKNOWN')
        threat_score = quick_results.get('threat_score', 0)

        # Color code based on threat level
        if threat_level == 'HIGH RISK':
            level_color = "red"
        elif threat_level == 'SUSPICIOUS':
            level_color = "yellow"
        else:
            level_color = "green"

        threat_panel = Panel(
            f"[bold white]{ip}[/bold white]\n"
            f"[{level_color}]{threat_level}[/{level_color}] (Score: {threat_score}/100)\n"
            f"Sources: {', '.join(quick_results.get('sources_checked', []))}\n"
            f"Analysis Time: {quick_results.get('analysis_time_ms', 0)}ms",
            title="Quick Assessment",
            border_style=level_color
        )

        self.console.print(threat_panel)

        # Key findings
        if quick_results.get('key_findings'):
            self.console.print(f"[bold]Key Findings:[/bold] {quick_results['key_findings']}")