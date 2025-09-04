#!/usr/bin/env python3
"""
SOC Forge - Advanced IP Threat Intelligence Tool
Main application entry point
"""

import os
import sys
import logging
from typing import Dict, Any
from dotenv import load_dotenv

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from soc_forge.cli.interface import SOCInterface
from soc_forge.core.ip_parser import IPParser
from soc_forge.core.analyzer import IPAnalyzer
from soc_forge.reports.generator import ReportGenerator


class SOCForgeApp:
    """Main SOC Forge application"""
    
    def __init__(self):
        # Load environment configuration
        load_dotenv()
        
        # Initialize logging
        self._setup_logging()
        
        # Initialize components
        self.interface = SOCInterface()
        self.parser = IPParser()
        self.analyzer = None
        self.report_generator = ReportGenerator()
        
        # Load API keys
        self.api_keys = self._load_api_keys()
        
        # Initialize analyzer with available keys
        if self.api_keys:
            self.analyzer = IPAnalyzer(self.api_keys)
        
        self.logger = logging.getLogger("soc_forge.main")
    
    def _setup_logging(self):
        """Setup application logging"""
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('outputs/logs/soc_forge.log'),
                logging.StreamHandler()
            ]
        )
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment"""
        api_keys = {}
        
        key_mappings = {
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'abuseipdb': 'ABUSEIPDB_API_KEY', 
            'ipinfo': 'IPINFO_API_KEY',
            'threatfox': 'THREATFOX_API_KEY',
            'greynoise': 'GREYNOISE_API_KEY'
        }
        
        for service, env_var in key_mappings.items():
            key = os.getenv(env_var)
            if key and key != f'your_{service}_api_key_here':
                api_keys[service] = key
        
        return api_keys
    
    def run(self):
        """Main application loop"""
        try:
            # Display banner
            self.interface.display_banner()
            
            # Check API availability
            if not self.api_keys:
                self.interface.console.print(
                    "[red]No API keys configured! Please check your .env file.[/red]"
                )
                return
            
            available_sources = list(self.api_keys.keys())
            self.interface.console.print(
                f"[green]Available sources:[/green] {', '.join(available_sources)}"
            )
            
            # Main loop
            while True:
                try:
                    # Get IP input
                    ip_input = self.interface.get_ip_input()
                    if not ip_input.strip():
                        self.interface.console.print("[yellow]Goodbye![/yellow]")
                        break
                    
                    # Parse IPs
                    parsing_result = self.parser.extract_ips(ip_input, include_private=False)
                    
                    # Display parsing results
                    if not self.interface.display_parsing_results(parsing_result):
                        continue
                    
                    # Store IPs for analysis
                    target_ips = parsing_result.valid_ips
                    
                    # Analysis menu loop
                    while True:
                        choice = self.interface.display_analysis_menu()
                        
                        if choice == "0":
                            self.interface.console.print("[yellow]Goodbye![/yellow]")
                            return
                        
                        elif choice == "1":
                            # Quick threat assessment
                            self._run_quick_assessment(target_ips)
                        
                        elif choice == "2":
                            # Comprehensive analysis
                            self._run_comprehensive_analysis(target_ips)
                        
                        elif choice == "3":
                            # GreyNoise quick check
                            self._run_greynoise_quick_check(target_ips)
                        
                        elif choice == "4":
                            # Malware & IOC analysis
                            self._run_malware_analysis(target_ips)
                        
                        elif choice == "5":
                            # Geolocation & network intel
                            self._run_network_analysis(target_ips)
                        
                        elif choice == "6":
                            # Generate KQL queries
                            self._generate_kql_queries(target_ips)
                        
                        elif choice == "7":
                            # Executive summary report
                            self._generate_executive_report(target_ips)
                        
                        elif choice == "8":
                            # Detailed technical report
                            self._generate_technical_report(target_ips)
                        
                        elif choice == "9":
                            # Advanced options
                            self._show_advanced_options()
                        
                        else:
                            self.interface.console.print("[red]Invalid option[/red]")
                        
                        # Ask if user wants to continue
                        if not self._continue_prompt():
                            break
                
                except KeyboardInterrupt:
                    self.interface.console.print("\n[yellow]Operation cancelled[/yellow]")
                    continue
                except Exception as e:
                    self.logger.error(f"Unexpected error: {str(e)}")
                    self.interface.console.print(f"[red]Error: {str(e)}[/red]")
                    continue
        
        except KeyboardInterrupt:
            self.interface.console.print("\n[yellow]Goodbye![/yellow]")
        except Exception as e:
            self.logger.error(f"Fatal error: {str(e)}")
            self.interface.console.print(f"[red]Fatal error: {str(e)}[/red]")
    
    def _run_quick_assessment(self, ips: list):
        """Run quick threat assessment"""
        self.interface.console.print("[bold cyan]Running Quick Threat Assessment...[/bold cyan]")
        
        # Use fast sources for quick check
        quick_sources = ['greynoise', 'abuseipdb']
        available_sources = [s for s in quick_sources if s in self.api_keys]
        
        if not available_sources:
            self.interface.console.print("[red]No quick assessment sources available[/red]")
            return
        
        results = self.analyzer.analyze_multiple_ips(ips, available_sources)
        self.interface.display_threat_summary(results)
    
    def _run_comprehensive_analysis(self, ips: list):
        """Run comprehensive analysis across all sources"""
        self.interface.console.print("[bold cyan]Running Comprehensive Analysis...[/bold cyan]")
        
        available_sources = list(self.api_keys.keys())
        self.interface.display_analysis_progress(ips, available_sources)
        
        results = self.analyzer.analyze_multiple_ips(ips)
        self.interface.display_threat_summary(results)
        
        # Show detailed results for each IP
        for ip in ips:
            if ip in results:
                self.interface.console.print("\n" + "="*80)
                self.interface.display_detailed_analysis(ip, results[ip].data)
    
    def _run_greynoise_quick_check(self, ips: list):
        """Run GreyNoise-specific analysis"""
        if 'greynoise' not in self.api_keys:
            self.interface.console.print("[red]GreyNoise API key not configured[/red]")
            return
        
        self.interface.console.print("[bold cyan]Running GreyNoise Analysis...[/bold cyan]")
        results = self.analyzer.analyze_multiple_ips(ips, ['greynoise'])
        self.interface.display_threat_summary(results)
    
    def _run_malware_analysis(self, ips: list):
        """Run malware-focused analysis"""
        malware_sources = ['virustotal', 'threatfox']
        available_sources = [s for s in malware_sources if s in self.api_keys]
        
        if not available_sources:
            self.interface.console.print("[red]No malware analysis sources available[/red]")
            return
        
        self.interface.console.print("[bold cyan]Running Malware & IOC Analysis...[/bold cyan]")
        results = self.analyzer.analyze_multiple_ips(ips, available_sources)
        self.interface.display_threat_summary(results)
    
    def _run_network_analysis(self, ips: list):
        """Run network and geolocation analysis"""
        if 'ipinfo' not in self.api_keys:
            self.interface.console.print("[red]IPInfo API key not configured[/red]")
            return
        
        self.interface.console.print("[bold cyan]Running Network & Geolocation Analysis...[/bold cyan]")
        results = self.analyzer.analyze_multiple_ips(ips, ['ipinfo'])
        
        # Display network-specific information
        for ip in ips:
            if ip in results and results[ip].success:
                self.interface.display_detailed_analysis(ip, results[ip].data)
    
    def _generate_kql_queries(self, ips: list):
        """Generate KQL queries for security analytics"""
        from soc_forge.utils.kql_generator import KQLGenerator
        
        generator = KQLGenerator()
        
        # Generate different types of Kibana KQL queries
        queries = {
            "Source IP Analysis": generator.generate_source_ip_query(ips),
            "Destination IP Analysis": generator.generate_destination_ip_query(ips), 
            "Combined Source/Destination": generator.generate_combined_ip_query(ips),
            "Network Traffic Patterns": generator.generate_traffic_analysis_query(ips),
            "Security Events": generator.generate_security_events_query(ips),
            "DNS Analysis": generator.generate_dns_analysis_query(ips),
            "Web/HTTP Analysis": generator.generate_web_analysis_query(ips),
            "Threat Hunting": generator.generate_threat_hunting_query(ips)
        }
        
        for query_type, query in queries.items():
            self.interface.console.print(f"\n[bold cyan]{query_type}:[/bold cyan]")
            self.interface.console.print(f"[green]{query}[/green]")
    
    def _generate_executive_report(self, ips: list):
        """Generate executive summary report"""
        self.interface.console.print("[bold cyan]Generating Executive Summary...[/bold cyan]")
        
        # Run analysis if needed
        results = self.analyzer.analyze_multiple_ips(ips)
        
        # Generate report
        report_path = self.report_generator.generate_executive_summary(results)
        self.interface.console.print(f"[green]Executive report saved: {report_path}[/green]")
    
    def _generate_technical_report(self, ips: list):
        """Generate detailed technical report"""
        self.interface.console.print("[bold cyan]Generating Technical Report...[/bold cyan]")
        
        # Run analysis if needed
        results = self.analyzer.analyze_multiple_ips(ips)
        
        # Generate report  
        report_path = self.report_generator.generate_technical_report(results)
        self.interface.console.print(f"[green]Technical report saved: {report_path}[/green]")
    
    def _show_advanced_options(self):
        """Show advanced configuration options"""
        self.interface.console.print("[bold cyan]Advanced Options[/bold cyan]")
        
        # Show API status
        api_status = self.analyzer.test_api_connections()
        for source, status in api_status.items():
            status_icon = "[OK]" if status else "[FAIL]"
            self.interface.console.print(f"{status_icon} {source.title()}")
        
        # Show configuration
        self.interface.console.print(f"\n[dim]Log Level: {os.getenv('LOG_LEVEL', 'INFO')}[/dim]")
        self.interface.console.print(f"[dim]Output Directory: {os.getenv('OUTPUT_DIR', 'outputs')}[/dim]")
        self.interface.console.print(f"[dim]Max Concurrent Requests: {os.getenv('MAX_CONCURRENT_REQUESTS', '5')}[/dim]")
    
    def _continue_prompt(self) -> bool:
        """Ask user if they want to continue"""
        response = self.interface.console.input("\n[bold cyan]Continue with this session? (Y/n):[/bold cyan] ")
        return response.lower() not in ['n', 'no', 'exit', 'quit']


def main():
    """Application entry point"""
    # Ensure output directories exist
    os.makedirs('outputs/reports', exist_ok=True)
    os.makedirs('outputs/logs', exist_ok=True)
    
    # Run application
    app = SOCForgeApp()
    app.run()


if __name__ == "__main__":
    main()