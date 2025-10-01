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
            'greynoise': 'GREYNOISE_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'otx': 'OTX_API_KEY'
        }
        
        for service, env_var in key_mappings.items():
            key = os.getenv(env_var)
            if key and key != f'your_{service}_api_key_here':
                api_keys[service] = key
        
        return api_keys
    
    def run(self):
        """Main application loop"""
        try:
            # Display banner with available sources
            available_sources = list(self.api_keys.keys()) if self.api_keys else []
            self.interface.display_banner(available_sources)

            # Check API availability
            if not self.api_keys:
                self.interface.console.print(
                    "[red]No API keys configured! Please check your .env file.[/red]"
                )
                return

            # Main menu loop
            while True:
                try:
                    # Display main menu
                    choice = self.interface.display_main_menu()

                    if choice == "0":
                        self.interface.console.print("[yellow]Goodbye![/yellow]")
                        break

                    elif choice == "1":
                        # Threat Scan
                        self._run_threat_scan()

                    elif choice == "2":
                        # Generate SIEM/Kibana Queries
                        self.interface.generate_siem_queries()
                        self._continue_prompt()

                    elif choice == "3":
                        # API Configuration & Health Check
                        self.interface.display_api_health_check(self.analyzer)
                        self._continue_prompt()

                    else:
                        self.interface.console.print("[red]Invalid option. Please select 0-3.[/red]")
                
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

    def _run_threat_scan(self):
        """Run threat scan functionality"""
        # Get IP input
        ip_input = self.interface.get_ip_input()
        if not ip_input.strip():
            return

        # Parse IPs
        parsing_result = self.parser.extract_ips(ip_input, include_private=False)

        # Display parsing results
        if not self.interface.display_parsing_results(parsing_result):
            return

        # Store IPs for analysis
        target_ips = parsing_result.valid_ips

        # Show progress message
        self.interface.console.print("\nProceeding with Threat Intelligence Collection...")

        # Run dashboard analysis
        self.interface.run_dashboard_analysis(target_ips, self.analyzer)

        # Ask if user wants to continue
        self._continue_prompt()

    def _continue_prompt(self) -> bool:
        """Ask user if they want to analyze more IPs"""
        response = self.interface.console.input("\n[bold cyan]Analyze more IPs? (Y/n):[/bold cyan] ")
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