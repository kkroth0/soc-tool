"""
VirusTotal API Client
Integration with VirusTotal threat intelligence platform
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class VirusTotalClient(BaseAPIClient):
    """Client for VirusTotal API"""
    
    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://www.virustotal.com/api/v3",
            name="virustotal"
        )
        
        # Add API key to headers
        self.session.headers.update({
            'x-apikey': api_key
        })
    
    def check_ip(self, ip: str) -> APIResult:
        """
        Check IP against VirusTotal database
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with VirusTotal analysis data
        """
        result = self._make_request(
            method="GET",
            endpoint=f"/ip_addresses/{ip}"
        )
        
        if not result.success:
            return result
        
        # Parse VirusTotal response
        parsed_data = self._parse_virustotal_response(result.data)
        result.data = parsed_data
        
        return result
    
    def _parse_virustotal_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal API response into standardized format"""
        
        parsed = {
            "source": "VirusTotal",
            "found": False,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "harmless": 0,
            "timeout": 0,
            "total_engines": 0,
            "reputation": 0,
            "last_analysis_date": None,
            "country": None,
            "asn": None,
            "as_owner": None,
            "network": None,
            "malware_families": [],
            "categories": [],
            "engines_detected": [],
            "engines_clean": [],
            "engines_timeout": [],
            "engines_detailed": {},
            "vendor_detection_ratio": "0/0",
            "raw_data": raw_data
        }
        
        if "data" not in raw_data:
            return parsed
        
        data = raw_data["data"]
        attributes = data.get("attributes", {})
        
        parsed["found"] = True
        
        # Analysis statistics
        stats = attributes.get("last_analysis_stats", {})
        parsed["malicious"] = stats.get("malicious", 0)
        parsed["suspicious"] = stats.get("suspicious", 0)
        parsed["undetected"] = stats.get("undetected", 0)
        parsed["harmless"] = stats.get("harmless", 0)
        parsed["timeout"] = stats.get("timeout", 0)
        
        parsed["total_engines"] = sum([
            parsed["malicious"],
            parsed["suspicious"], 
            parsed["undetected"],
            parsed["harmless"],
            parsed["timeout"]
        ])
        
        # Reputation score
        parsed["reputation"] = attributes.get("reputation", 0)
        
        # Analysis date
        parsed["last_analysis_date"] = attributes.get("last_analysis_date")
        
        # Network information
        parsed["country"] = attributes.get("country")
        parsed["asn"] = attributes.get("asn")
        parsed["as_owner"] = attributes.get("as_owner")
        parsed["network"] = attributes.get("network")
        
        # Malware families and categories
        parsed["malware_families"] = list(attributes.get("malware_families", {}).keys())
        
        # Categories from different sources
        categories = set()
        category_sources = ["Alexa", "Bitdefender", "Dr.Web", "Forcepoint ThreatSeeker", "sophos"]
        for source in category_sources:
            if source in attributes.get("categories", {}):
                categories.add(attributes["categories"][source])
        parsed["categories"] = list(categories)
        
        # Detailed engine analysis results
        results = attributes.get("last_analysis_results", {})
        engines_detected = []
        engines_clean = []
        engines_timeout = []

        for engine_name, engine_result in results.items():
            engine_info = {
                "engine": engine_name,
                "category": engine_result.get("category"),
                "result": engine_result.get("result"),
                "method": engine_result.get("method"),
                "engine_version": engine_result.get("engine_version"),
                "engine_update": engine_result.get("engine_update")
            }

            category = engine_result.get("category")
            if category in ["malicious", "suspicious"]:
                engines_detected.append(engine_info)
            elif category == "harmless":
                engines_clean.append(engine_info)
            elif category == "timeout":
                engines_timeout.append(engine_info)

        parsed["engines_detected"] = engines_detected
        parsed["engines_clean"] = engines_clean
        parsed["engines_timeout"] = engines_timeout
        parsed["engines_detailed"] = results

        # Calculate vendor detection ratio
        total_detected = parsed["malicious"] + parsed["suspicious"]
        parsed["vendor_detection_ratio"] = f"{total_detected}/{parsed['total_engines']}"

        return parsed
    
    def get_ip_comments(self, ip: str, limit: int = 10) -> APIResult:
        """
        Get comments for an IP address
        
        Args:
            ip: IP address
            limit: Maximum number of comments to retrieve
            
        Returns:
            APIResult with comments data
        """
        params = {"limit": limit}
        
        return self._make_request(
            method="GET",
            endpoint=f"/ip_addresses/{ip}/comments",
            params=params
        )
    
    def get_communicating_files(self, ip: str, limit: int = 10) -> APIResult:
        """
        Get files communicating with the IP
        
        Args:
            ip: IP address
            limit: Maximum number of files to retrieve
            
        Returns:
            APIResult with communicating files data
        """
        params = {"limit": limit}
        
        return self._make_request(
            method="GET",
            endpoint=f"/ip_addresses/{ip}/communicating_files",
            params=params
        )