"""
AbuseIPDB API Client
Integration with AbuseIPDB threat intelligence database
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class AbuseIPDBClient(BaseAPIClient):
    """Client for AbuseIPDB API"""
    
    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://api.abuseipdb.com/api/v2",
            name="abuseipdb"
        )
        
        # Add API key to headers
        self.session.headers.update({
            'Key': api_key,
            'Accept': 'application/json'
        })
    
    def check_ip(self, ip: str, max_age_days: int = 90, verbose: bool = True) -> APIResult:
        """
        Check IP against AbuseIPDB database
        
        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports to consider
            verbose: Include detailed report information
            
        Returns:
            APIResult with AbuseIPDB analysis data
        """
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": verbose
        }
        
        result = self._make_request(
            method="GET",
            endpoint="/check",
            params=params
        )
        
        if not result.success:
            return result
        
        # Parse AbuseIPDB response
        parsed_data = self._parse_abuseipdb_response(result.data)
        result.data = parsed_data
        
        return result
    
    def _parse_abuseipdb_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB API response into standardized format"""
        
        parsed = {
            "source": "AbuseIPDB",
            "found": False,
            "confidence_score": 0,
            "abuse_confidence": 0,
            "country_code": None,
            "country_name": None,
            "usage_type": None,
            "isp": None,
            "domain": None,
            "hostnames": [],
            "total_reports": 0,
            "num_distinct_users": 0,
            "last_reported": None,
            "first_reported": None,
            "is_whitelisted": False,
            "is_public": None,
            "categories": [],
            "raw_data": raw_data
        }
        
        if "data" not in raw_data:
            return parsed
        
        data = raw_data["data"]
        parsed["found"] = True
        
        # Core abuse data
        parsed["confidence_score"] = data.get("abuseConfidenceScore", 0)
        parsed["abuse_confidence"] = parsed["confidence_score"]  # Alias
        
        # Geographic information
        parsed["country_code"] = data.get("countryCode")
        parsed["country_name"] = data.get("countryName")
        
        # Network information
        parsed["usage_type"] = data.get("usageType")
        parsed["isp"] = data.get("isp")
        parsed["domain"] = data.get("domain")
        parsed["hostnames"] = data.get("hostnames", [])
        
        # Report statistics
        parsed["total_reports"] = data.get("totalReports", 0)
        parsed["num_distinct_users"] = data.get("numDistinctUsers", 0)
        parsed["last_reported"] = data.get("lastReportedAt")
        
        # Additional flags
        parsed["is_whitelisted"] = data.get("isWhitelisted", False)
        parsed["is_public"] = data.get("isPublic")
        
        # Parse report categories if verbose data is available
        if "reports" in data:
            categories = set()
            first_reports = []
            
            for report in data["reports"]:
                if "categories" in report:
                    categories.update(report["categories"])
                if "reportedAt" in report:
                    first_reports.append(report["reportedAt"])
            
            parsed["categories"] = list(categories)
            if first_reports:
                parsed["first_reported"] = min(first_reports)
        
        return parsed
    
    def report_ip(self, ip: str, categories: list, comment: str) -> APIResult:
        """
        Report an IP address to AbuseIPDB
        
        Args:
            ip: IP address to report
            categories: List of category IDs
            comment: Description of malicious activity
            
        Returns:
            APIResult with report submission status
        """
        payload = {
            "ip": ip,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }
        
        return self._make_request(
            method="POST",
            endpoint="/report",
            json_data=payload
        )
    
    def get_blacklist(self, confidence_minimum: int = 75, limit: int = 10000) -> APIResult:
        """
        Get blacklist of malicious IPs
        
        Args:
            confidence_minimum: Minimum confidence score (25-100)
            limit: Maximum number of IPs to return
            
        Returns:
            APIResult with blacklisted IPs
        """
        params = {
            "confidenceMinimum": max(25, min(100, confidence_minimum)),
            "limit": limit
        }
        
        return self._make_request(
            method="GET",
            endpoint="/blacklist",
            params=params
        )