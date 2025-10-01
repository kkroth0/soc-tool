"""
GreyNoise API Client
Integration with GreyNoise internet scanning intelligence
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class GreyNoiseClient(BaseAPIClient):
    """Client for GreyNoise API"""
    
    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://api.greynoise.io/v3",
            name="greynoise"
        )
        
        # Add API key to headers
        self.session.headers.update({
            'key': api_key
        })
    
    def check_ip(self, ip: str) -> APIResult:
        """
        Check IP against GreyNoise Community API

        Args:
            ip: IP address to check

        Returns:
            APIResult with GreyNoise context data
        """
        # Use Community API endpoint which is free
        result = self._make_request(
            method="GET",
            endpoint=f"/community/{ip}"
        )
        
        if not result.success:
            return result
        
        # Parse GreyNoise response
        parsed_data = self._parse_greynoise_response(result.data)
        result.data = parsed_data
        
        return result
    
    def _parse_greynoise_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GreyNoise API response into standardized format"""
        
        parsed = {
            "source": "GreyNoise",
            "found": False,
            "seen": False,
            "classification": "unknown",
            "first_seen": None,
            "last_seen": None,
            "actor": None,
            "tags": [],
            "cve": [],
            "malicious": False,
            "benign": False,
            "noise": False,
            "riot": False,
            "bot": False,
            "vpn": False,
            "vpn_service": None,
            "spoofable": False,
            "organization": None,
            "asn": None,
            "country": None,
            "country_code": None,
            "city": None,
            "raw_data": raw_data
        }
        
        # Check if IP was found
        if "ip" not in raw_data or raw_data.get("message") == "IP not observed scanning the internet or contained in RIOT data set":
            return parsed
        
        parsed["found"] = True
        parsed["seen"] = raw_data.get("seen", False)
        
        # Classification information
        parsed["classification"] = raw_data.get("classification", "unknown")
        parsed["malicious"] = parsed["classification"] == "malicious"
        parsed["benign"] = parsed["classification"] == "benign"
        
        # Noise and RIOT information
        parsed["noise"] = raw_data.get("noise", False)
        parsed["riot"] = raw_data.get("riot", False)
        
        # Dates
        parsed["first_seen"] = raw_data.get("first_seen")
        parsed["last_seen"] = raw_data.get("last_seen")
        
        # Actor information
        parsed["actor"] = raw_data.get("actor")
        
        # Tags and CVEs
        parsed["tags"] = raw_data.get("tags", [])
        parsed["cve"] = raw_data.get("cve", [])
        
        # VPN information
        parsed["vpn"] = raw_data.get("vpn", False)
        parsed["vpn_service"] = raw_data.get("vpn_service")
        
        # Technical information
        parsed["bot"] = raw_data.get("bot", False)
        parsed["spoofable"] = raw_data.get("spoofable", False)
        
        # Geographic and network information
        parsed["organization"] = raw_data.get("organization")
        parsed["asn"] = raw_data.get("asn")
        parsed["country"] = raw_data.get("country")
        parsed["country_code"] = raw_data.get("country_code")
        parsed["city"] = raw_data.get("city")
        
        return parsed
    
    def quick_check(self, ip: str) -> APIResult:
        """
        Quick check if IP is internet noise
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with quick noise classification
        """
        result = self._make_request(
            method="GET",
            endpoint=f"/noise/quick/{ip}"
        )
        
        if result.success:
            # Parse quick response
            noise_status = result.data.get("noise", False)
            code = result.data.get("code")
            
            result.data = {
                "source": "GreyNoise Quick",
                "is_noise": noise_status,
                "code": code,
                "message": self._get_noise_code_description(code)
            }
        
        return result
    
    def multi_quick_check(self, ips: list) -> APIResult:
        """
        Check multiple IPs quickly (up to 500)
        
        Args:
            ips: List of IP addresses to check
            
        Returns:
            APIResult with quick noise status for all IPs
        """
        # Limit to 500 IPs as per API limits
        ip_list = ips[:500]
        
        payload = {
            "ips": ip_list
        }
        
        result = self._make_request(
            method="POST",
            endpoint="/noise/multi/quick",
            json_data=payload
        )
        
        if result.success:
            # Parse multi-response
            parsed_results = {}
            for item in result.data:
                ip = item.get("ip")
                noise = item.get("noise", False)
                code = item.get("code")
                
                parsed_results[ip] = {
                    "is_noise": noise,
                    "code": code,
                    "message": self._get_noise_code_description(code)
                }
            
            result.data = {
                "source": "GreyNoise Multi-Quick",
                "results": parsed_results,
                "total_checked": len(ip_list)
            }
        
        return result
    
    def _get_noise_code_description(self, code: str) -> str:
        """Get description for GreyNoise response codes"""
        code_descriptions = {
            "0x00": "IP has never been observed scanning the internet",
            "0x01": "IP has been observed by the GreyNoise sensor network",
            "0x02": "IP has never been observed scanning the internet but is in RIOT",
            "0x03": "IP is commonly spoofed in Internet-scan traffic",
            "0x04": "IP has not been observed by the GreyNoise sensor network but has been observed in other data sources",
            "0x05": "IP is invalid",
            "0x06": "IP is in a reserved range",
            "0x07": "IP is commonly spoofed in Internet-scan traffic and is in RIOT",
            "0x08": "IP has not been observed by the GreyNoise sensor network but is in RIOT"
        }
        
        return code_descriptions.get(code, f"Unknown code: {code}")
    
    def get_riot_ip(self, ip: str) -> APIResult:
        """
        Get RIOT (Rule It Out) information for an IP
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with RIOT data
        """
        result = self._make_request(
            method="GET",
            endpoint=f"/riot/{ip}"
        )
        
        if result.success:
            riot_data = result.data
            result.data = {
                "source": "GreyNoise RIOT",
                "found": "riot" in riot_data and riot_data["riot"],
                "name": riot_data.get("name"),
                "description": riot_data.get("description"),
                "explanation": riot_data.get("explanation"),
                "last_updated": riot_data.get("last_updated"),
                "reference": riot_data.get("reference"),
                "trust_level": riot_data.get("trust_level"),
                "category": riot_data.get("category"),
                "raw_data": riot_data
            }
        
        return result