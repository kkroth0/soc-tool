"""
IPInfo API Client
Integration with IPInfo geolocation and network intelligence
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class IPInfoClient(BaseAPIClient):
    """Client for IPInfo API"""
    
    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://ipinfo.io",
            name="ipinfo"
        )
    
    def check_ip(self, ip: str) -> APIResult:
        """
        Get comprehensive information about an IP address
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with IPInfo data
        """
        params = {"token": self.api_key}
        
        result = self._make_request(
            method="GET",
            endpoint=f"/{ip}/json",
            params=params
        )
        
        if not result.success:
            return result
        
        # Parse IPInfo response
        parsed_data = self._parse_ipinfo_response(result.data)
        result.data = parsed_data
        
        return result
    
    def _parse_ipinfo_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IPInfo API response into standardized format"""
        
        parsed = {
            "source": "IPInfo",
            "found": True,
            "ip": raw_data.get("ip"),
            "hostname": raw_data.get("hostname"),
            "city": raw_data.get("city"),
            "region": raw_data.get("region"),
            "country": raw_data.get("country"),
            "country_name": None,
            "location": raw_data.get("loc"),
            "organization": raw_data.get("org"),
            "postal": raw_data.get("postal"),
            "timezone": raw_data.get("timezone"),
            "asn": None,
            "asn_name": None,
            "asn_domain": None,
            "asn_route": None,
            "asn_type": None,
            "company_name": None,
            "company_domain": None,
            "company_type": None,
            "carrier_name": None,
            "carrier_mcc": None,
            "carrier_mnc": None,
            "privacy_vpn": False,
            "privacy_proxy": False,
            "privacy_tor": False,
            "privacy_relay": False,
            "privacy_hosting": False,
            "privacy_service": None,
            "abuse_address": None,
            "abuse_country": None,
            "abuse_email": None,
            "abuse_name": None,
            "abuse_network": None,
            "abuse_phone": None,
            "domains_count": 0,
            "domains_list": [],
            "raw_data": raw_data
        }
        
        # Parse location coordinates
        if parsed["location"]:
            try:
                lat, lon = parsed["location"].split(",")
                parsed["latitude"] = float(lat)
                parsed["longitude"] = float(lon)
            except (ValueError, AttributeError):
                parsed["latitude"] = None
                parsed["longitude"] = None
        
        # Parse organization/ASN information
        org = raw_data.get("org", "")
        if org.startswith("AS"):
            try:
                asn_part, name_part = org.split(" ", 1)
                parsed["asn"] = asn_part[2:]  # Remove "AS" prefix
                parsed["asn_name"] = name_part
            except ValueError:
                parsed["asn_name"] = org
        else:
            parsed["asn_name"] = org
        
        return parsed
    
    def get_asn_info(self, asn: str) -> APIResult:
        """
        Get detailed ASN information
        
        Args:
            asn: ASN number (with or without AS prefix)
            
        Returns:
            APIResult with ASN details
        """
        # Ensure ASN has AS prefix
        if not asn.startswith("AS"):
            asn = f"AS{asn}"
        
        params = {"token": self.api_key}
        
        return self._make_request(
            method="GET",
            endpoint=f"/{asn}/json",
            params=params
        )
    
    def get_privacy_info(self, ip: str) -> APIResult:
        """
        Get privacy/VPN/proxy information for an IP
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with privacy information
        """
        params = {"token": self.api_key}
        
        result = self._make_request(
            method="GET",
            endpoint=f"/{ip}/privacy",
            params=params
        )
        
        if result.success:
            privacy_data = result.data
            result.data = {
                "source": "IPInfo Privacy",
                "vpn": privacy_data.get("vpn", False),
                "proxy": privacy_data.get("proxy", False),
                "tor": privacy_data.get("tor", False),
                "relay": privacy_data.get("relay", False),
                "hosting": privacy_data.get("hosting", False),
                "service": privacy_data.get("service"),
                "raw_data": privacy_data
            }
        
        return result
    
    def get_company_info(self, ip: str) -> APIResult:
        """
        Get company information for an IP
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with company information
        """
        params = {"token": self.api_key}
        
        return self._make_request(
            method="GET",
            endpoint=f"/{ip}/company",
            params=params
        )
    
    def get_abuse_info(self, ip: str) -> APIResult:
        """
        Get abuse contact information for an IP
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with abuse contact information
        """
        params = {"token": self.api_key}
        
        return self._make_request(
            method="GET",
            endpoint=f"/{ip}/abuse",
            params=params
        )
    
    def get_hosted_domains(self, ip: str) -> APIResult:
        """
        Get domains hosted on an IP address
        
        Args:
            ip: IP address to check
            
        Returns:
            APIResult with hosted domains
        """
        params = {"token": self.api_key}
        
        return self._make_request(
            method="GET",
            endpoint=f"/{ip}/domains",
            params=params
        )