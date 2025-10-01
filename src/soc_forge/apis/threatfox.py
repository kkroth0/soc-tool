"""
ThreatFox API Client
Integration with abuse.ch ThreatFox threat intelligence platform
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class ThreatFoxClient(BaseAPIClient):
    """Client for ThreatFox API"""

    def __init__(self, api_key: str = "public"):
        # ThreatFox API is free and doesn't require authentication
        super().__init__(
            api_key=api_key,
            base_url="https://threatfox-api.abuse.ch/api/v1",
            name="threatfox"
        )
    
    def check_ip(self, ip: str) -> APIResult:
        """
        Search for IP in ThreatFox IOCs

        Args:
            ip: IP address to check

        Returns:
            APIResult with ThreatFox data
        """
        payload = {
            "query": "search_ioc",
            "search_term": ip
        }

        # ThreatFox doesn't require auth headers, just POST the data
        result = self._make_request(
            method="POST",
            endpoint="",
            json_data=payload
        )
        
        if not result.success:
            return result
        
        # Parse ThreatFox response
        parsed_data = self._parse_threatfox_response(result.data)
        result.data = parsed_data
        
        return result
    
    def _parse_threatfox_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse ThreatFox API response into standardized format"""
        
        parsed = {
            "source": "ThreatFox",
            "found": False,
            "ioc_count": 0,
            "threat_types": [],
            "malware_families": [],
            "first_seen": None,
            "last_seen": None,
            "confidence_level": 0,
            "tags": [],
            "iocs": []
        }
        
        if raw_data.get("query_status") != "ok":
            parsed["error"] = raw_data.get("query_status", "Unknown error")
            return parsed
        
        iocs = raw_data.get("data", [])
        if not iocs:
            return parsed
        
        parsed["found"] = True
        parsed["ioc_count"] = len(iocs)
        
        # Extract information from IOCs
        threat_types = set()
        malware_families = set()
        tags = set()
        first_seen_dates = []
        last_seen_dates = []
        confidence_levels = []
        
        for ioc in iocs:
            # Collect threat information
            if ioc.get("threat_type"):
                threat_types.add(ioc["threat_type"])
            
            if ioc.get("malware"):
                malware_families.add(ioc["malware"])
            
            if ioc.get("tags"):
                tags.update(ioc["tags"])
            
            # Collect dates
            if ioc.get("first_seen"):
                first_seen_dates.append(ioc["first_seen"])
            
            if ioc.get("last_seen"):
                last_seen_dates.append(ioc["last_seen"])
            
            # Collect confidence
            if ioc.get("confidence_level"):
                confidence_levels.append(ioc["confidence_level"])
            
            # Store IOC details
            parsed["iocs"].append({
                "id": ioc.get("id"),
                "ioc": ioc.get("ioc"),
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "confidence_level": ioc.get("confidence_level", 0),
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "reference": ioc.get("reference"),
                "tags": ioc.get("tags", [])
            })
        
        # Aggregate information
        parsed["threat_types"] = list(threat_types)
        parsed["malware_families"] = list(malware_families)
        parsed["tags"] = list(tags)
        
        # Get most recent dates
        if first_seen_dates:
            parsed["first_seen"] = min(first_seen_dates)
        if last_seen_dates:
            parsed["last_seen"] = max(last_seen_dates)
        
        # Calculate average confidence
        if confidence_levels:
            parsed["confidence_level"] = sum(confidence_levels) / len(confidence_levels)
        
        return parsed
    
    def get_recent_iocs(self, days: int = 1) -> APIResult:
        """
        Get recent IOCs from ThreatFox
        
        Args:
            days: Number of days back to search (1-7)
            
        Returns:
            APIResult with recent IOCs
        """
        payload = {
            "query": "get_iocs",
            "days": min(max(days, 1), 7)  # Clamp between 1-7 days
        }
        
        return self._make_request(
            method="POST",
            endpoint="/",
            json_data=payload
        )
    
    def search_hash(self, hash_value: str) -> APIResult:
        """
        Search for a hash in ThreatFox
        
        Args:
            hash_value: MD5, SHA1, or SHA256 hash
            
        Returns:
            APIResult with hash information
        """
        payload = {
            "query": "search_hash",
            "hash": hash_value
        }
        
        return self._make_request(
            method="POST",
            endpoint="/",
            json_data=payload
        )