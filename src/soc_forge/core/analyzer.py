"""
Core IP Analyzer
Orchestrates analysis across multiple threat intelligence sources
"""

import asyncio
import concurrent.futures
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass
import time

from ..apis.virustotal import VirusTotalClient
from ..apis.abuseipdb import AbuseIPDBClient
from ..apis.ipinfo import IPInfoClient
from ..apis.threatfox import ThreatFoxClient
from ..apis.greynoise import GreyNoiseClient
from ..apis.base import APIResult


@dataclass
class AnalysisResult:
    """Complete analysis result for an IP"""
    ip: str
    analysis_time_ms: int
    success: bool
    error: Optional[str]
    sources_queried: List[str]
    sources_successful: List[str]
    data: Dict[str, Any]


class IPAnalyzer:
    """Core IP analysis engine"""
    
    def __init__(self, api_keys: Dict[str, str], max_workers: int = 5):
        self.logger = logging.getLogger("soc_forge.analyzer")
        self.max_workers = max_workers
        
        # Initialize API clients
        self.clients = {}
        
        if api_keys.get('virustotal'):
            self.clients['virustotal'] = VirusTotalClient(api_keys['virustotal'])
        
        if api_keys.get('abuseipdb'):
            self.clients['abuseipdb'] = AbuseIPDBClient(api_keys['abuseipdb'])
        
        if api_keys.get('ipinfo'):
            self.clients['ipinfo'] = IPInfoClient(api_keys['ipinfo'])
        
        if api_keys.get('threatfox'):
            self.clients['threatfox'] = ThreatFoxClient(api_keys['threatfox'])
        
        if api_keys.get('greynoise'):
            self.clients['greynoise'] = GreyNoiseClient(api_keys['greynoise'])
        
        self.logger.info(f"Initialized analyzer with {len(self.clients)} API sources")
    
    def analyze_single_ip(self, ip: str, sources: Optional[List[str]] = None) -> AnalysisResult:
        """
        Analyze a single IP across specified sources
        
        Args:
            ip: IP address to analyze
            sources: List of sources to query (None = all available)
            
        Returns:
            AnalysisResult with complete analysis data
        """
        start_time = time.time()
        
        if sources is None:
            sources = list(self.clients.keys())
        
        # Filter to available clients
        sources = [s for s in sources if s in self.clients]
        
        if not sources:
            return AnalysisResult(
                ip=ip,
                analysis_time_ms=0,
                success=False,
                error="No API sources available",
                sources_queried=[],
                sources_successful=[],
                data={}
            )
        
        results = {}
        successful_sources = []
        
        # Query each source
        for source in sources:
            try:
                client = self.clients[source]
                result = client.check_ip(ip)
                
                if result.success:
                    results[source] = result.data
                    successful_sources.append(source)
                    self.logger.debug(f"Successfully queried {source} for {ip}")
                else:
                    self.logger.warning(f"Failed to query {source} for {ip}: {result.error}")
                    results[source] = {"error": result.error, "success": False}
                
            except Exception as e:
                self.logger.error(f"Exception querying {source} for {ip}: {str(e)}")
                results[source] = {"error": str(e), "success": False}
        
        analysis_time_ms = int((time.time() - start_time) * 1000)
        
        return AnalysisResult(
            ip=ip,
            analysis_time_ms=analysis_time_ms,
            success=len(successful_sources) > 0,
            error=None if successful_sources else "All sources failed",
            sources_queried=sources,
            sources_successful=successful_sources,
            data=results
        )
    
    def analyze_multiple_ips(self, ips: List[str], 
                           sources: Optional[List[str]] = None) -> Dict[str, AnalysisResult]:
        """
        Analyze multiple IPs concurrently
        
        Args:
            ips: List of IP addresses to analyze
            sources: List of sources to query (None = all available)
            
        Returns:
            Dictionary mapping IP addresses to AnalysisResults
        """
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all analysis tasks
            future_to_ip = {
                executor.submit(self.analyze_single_ip, ip, sources): ip 
                for ip in ips
            }
            
            results = {}
            completed = 0
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    results[ip] = result
                    completed += 1
                    
                    self.logger.info(f"Completed analysis for {ip} ({completed}/{len(ips)})")
                    
                except Exception as e:
                    self.logger.error(f"Analysis failed for {ip}: {str(e)}")
                    results[ip] = AnalysisResult(
                        ip=ip,
                        analysis_time_ms=0,
                        success=False,
                        error=str(e),
                        sources_queried=sources or [],
                        sources_successful=[],
                        data={}
                    )
        
        total_time = time.time() - start_time
        self.logger.info(f"Completed analysis of {len(ips)} IPs in {total_time:.2f}s")
        
        return results
    
    def quick_reputation_check(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Quick reputation check focusing on fast sources
        
        Args:
            ips: List of IP addresses to check
            
        Returns:
            Dictionary with quick reputation results
        """
        # Use fast sources for quick checks
        quick_sources = []
        
        if 'greynoise' in self.clients:
            quick_sources.append('greynoise')
        if 'abuseipdb' in self.clients:
            quick_sources.append('abuseipdb')
        
        if not quick_sources:
            return {}
        
        results = self.analyze_multiple_ips(ips, quick_sources)
        
        # Simplify results for quick assessment
        quick_results = {}
        for ip, result in results.items():
            quick_results[ip] = {
                'threat_level': self._assess_quick_threat_level(result.data),
                'sources_checked': result.sources_successful,
                'analysis_time_ms': result.analysis_time_ms
            }
        
        return quick_results
    
    def _assess_quick_threat_level(self, data: Dict[str, Any]) -> str:
        """Assess threat level from quick check data"""
        
        # Check GreyNoise classification
        if 'greynoise' in data:
            gn_data = data['greynoise']
            if gn_data.get('malicious'):
                return 'HIGH'
            elif gn_data.get('classification') == 'benign':
                return 'LOW'
        
        # Check AbuseIPDB confidence
        if 'abuseipdb' in data:
            abuse_data = data['abuseipdb']
            confidence = abuse_data.get('confidence_score', 0)
            if confidence >= 75:
                return 'HIGH'
            elif confidence >= 25:
                return 'MEDIUM'
        
        return 'LOW'
    
    def get_available_sources(self) -> List[str]:
        """Get list of available API sources"""
        return list(self.clients.keys())
    
    def test_api_connections(self) -> Dict[str, bool]:
        """Test connectivity to all configured APIs"""
        results = {}
        
        for source, client in self.clients.items():
            try:
                # Simple connectivity test
                test_result = client.test_connection()
                results[source] = test_result.success
            except Exception:
                results[source] = False
        
        return results
    
    def get_source_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics about API usage and performance"""
        # This would be enhanced with actual usage tracking
        stats = {}
        
        for source in self.clients.keys():
            stats[source] = {
                'available': True,
                'last_used': None,  # Would track actual usage
                'success_rate': None,  # Would calculate from usage history
                'avg_response_time_ms': None  # Would track response times
            }
        
        return stats