"""
Shodan API Client
Integration with Shodan for port scanning and service detection data
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class ShodanClient(BaseAPIClient):
    """Client for Shodan API"""

    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://api.shodan.io",
            name="shodan"
        )

        # Add API key to params (Shodan uses key parameter)
        self.default_params = {'key': api_key}

    def check_ip(self, ip: str) -> APIResult:
        """
        Check IP against Shodan database for open ports and services

        Args:
            ip: IP address to check

        Returns:
            APIResult with Shodan host information
        """
        result = self._make_request(
            method="GET",
            endpoint=f"/shodan/host/{ip}",
            params=self.default_params
        )

        if not result.success:
            return result

        # Parse Shodan response
        parsed_data = self._parse_shodan_response(result.data)
        result.data = parsed_data

        return result

    def _parse_shodan_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Shodan API response into standardized format"""

        parsed = {
            "source": "Shodan",
            "found": False,
            "ip": None,
            "hostnames": [],
            "ports": [],
            "services": [],
            "operating_system": None,
            "organization": None,
            "isp": None,
            "country_name": None,
            "city": None,
            "region_code": None,
            "postal_code": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "vulnerabilities": [],
            "tags": [],
            "last_update": None,
            "raw_data": raw_data
        }

        if "error" in raw_data:
            return parsed

        parsed["found"] = True
        parsed["ip"] = raw_data.get("ip_str")
        parsed["hostnames"] = raw_data.get("hostnames", [])
        parsed["operating_system"] = raw_data.get("os")
        parsed["organization"] = raw_data.get("org")
        parsed["isp"] = raw_data.get("isp")
        parsed["country_name"] = raw_data.get("country_name")
        parsed["city"] = raw_data.get("city")
        parsed["region_code"] = raw_data.get("region_code")
        parsed["postal_code"] = raw_data.get("postal_code")
        parsed["latitude"] = raw_data.get("latitude")
        parsed["longitude"] = raw_data.get("longitude")
        parsed["asn"] = raw_data.get("asn")
        parsed["tags"] = raw_data.get("tags", [])
        parsed["last_update"] = raw_data.get("last_update")

        # Parse vulnerabilities
        vulns = raw_data.get("vulns", [])
        parsed["vulnerabilities"] = vulns

        # Parse port and service information
        data_entries = raw_data.get("data", [])
        ports = set()
        services = []

        for entry in data_entries:
            port = entry.get("port")
            if port:
                ports.add(port)

                service_info = {
                    "port": port,
                    "protocol": entry.get("transport", "tcp"),
                    "service": entry.get("product", "").split()[0] if entry.get("product") else "",
                    "product": entry.get("product", ""),
                    "version": entry.get("version", ""),
                    "banner": entry.get("data", "").strip()[:100],  # Limit banner length
                    "ssl": entry.get("ssl") is not None,
                    "timestamp": entry.get("timestamp")
                }
                services.append(service_info)

        parsed["ports"] = sorted(list(ports))
        parsed["services"] = services

        return parsed

    def get_host_info(self, ip: str) -> APIResult:
        """
        Get comprehensive host information from Shodan

        Args:
            ip: IP address to query

        Returns:
            APIResult with detailed host information
        """
        return self.check_ip(ip)

    def search_query(self, query: str, limit: int = 10) -> APIResult:
        """
        Search Shodan using a query string

        Args:
            query: Shodan search query
            limit: Maximum number of results

        Returns:
            APIResult with search results
        """
        params = self.default_params.copy()
        params.update({
            'query': query,
            'limit': limit
        })

        return self._make_request(
            method="GET",
            endpoint="/shodan/host/search",
            params=params
        )

    def get_api_info(self) -> APIResult:
        """
        Get API plan information and usage statistics

        Returns:
            APIResult with API information
        """
        return self._make_request(
            method="GET",
            endpoint="/api-info",
            params=self.default_params
        )

    def test_connection(self) -> APIResult:
        """Test Shodan API connection"""
        return self.get_api_info()