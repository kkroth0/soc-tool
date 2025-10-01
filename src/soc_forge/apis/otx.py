"""
AlienVault OTX (Open Threat Exchange) API Client
Integration with AlienVault OTX for threat intelligence data
"""

from typing import Dict, Any
from .base import BaseAPIClient, APIResult


class OTXClient(BaseAPIClient):
    """Client for AlienVault OTX API"""

    def __init__(self, api_key: str):
        super().__init__(
            api_key=api_key,
            base_url="https://otx.alienvault.com/api/v1",
            name="otx"
        )

        # Add API key to headers (OTX uses X-OTX-API-KEY header)
        self.session.headers.update({
            'X-OTX-API-KEY': api_key
        })

    def check_ip(self, ip: str) -> APIResult:
        """
        Check IP against AlienVault OTX database
        Gets comprehensive data by combining multiple sections

        Args:
            ip: IP address to check

        Returns:
            APIResult with OTX threat intelligence data
        """
        # Get general information (includes pulse info)
        general_result = self._make_request(
            method="GET",
            endpoint=f"/indicators/IPv4/{ip}/general",
            timeout=10
        )

        if not general_result.success:
            return general_result

        # Parse OTX response - start with general data
        parsed_data = self._parse_otx_response(ip, general_result.data)

        # Fetch additional threat intelligence sections with timeout handling
        # These provide critical data like passive DNS, malware, and URLs

        # Get passive DNS (domains resolving to this IP)
        try:
            passive_dns_result = self._make_request(
                method="GET",
                endpoint=f"/indicators/IPv4/{ip}/passive_dns",
                timeout=8
            )
            if passive_dns_result.success and passive_dns_result.data:
                passive_dns = passive_dns_result.data.get("passive_dns", [])
                parsed_data["passive_dns_count"] = len(passive_dns)
                parsed_data["passive_dns"] = passive_dns[:100]  # Limit to first 100
        except Exception as e:
            parsed_data["passive_dns_count"] = 0
            parsed_data["passive_dns"] = []

        # Get malware/file analysis (includes AV detections)
        try:
            malware_result = self._make_request(
                method="GET",
                endpoint=f"/indicators/IPv4/{ip}/malware",
                timeout=8
            )
            if malware_result.success and malware_result.data:
                # Get total count from API response (not just data array length)
                parsed_data["malware_count"] = malware_result.data.get("count", 0)
                malware_data = malware_result.data.get("data", [])
                parsed_data["malware_samples"] = malware_data[:50]  # Limit to first 50

                # Extract AV detections (detections is a dict with AV names as keys)
                av_detections = set()
                for sample in malware_data[:50]:  # Check first 50 samples
                    if sample.get("detections"):
                        detections_dict = sample["detections"]
                        for av_name, detection in detections_dict.items():
                            if detection:  # Skip null detections
                                av_detections.add(detection)

                parsed_data["av_detections"] = sorted(list(av_detections))[:30]  # Top 30
        except Exception as e:
            parsed_data["malware_count"] = 0
            parsed_data["malware_samples"] = []
            parsed_data["av_detections"] = []

        # Get URL list (URLs hosted on this IP)
        try:
            url_result = self._make_request(
                method="GET",
                endpoint=f"/indicators/IPv4/{ip}/url_list",
                timeout=8
            )
            if url_result.success and url_result.data:
                url_list = url_result.data.get("url_list", [])
                parsed_data["url_count"] = len(url_list)
                parsed_data["url_list"] = url_list[:20]  # Limit to first 20
        except Exception as e:
            parsed_data["url_count"] = 0
            parsed_data["url_list"] = []

        # Calculate enhanced threat score based on all data
        parsed_data["threat_score"] = self._calculate_enhanced_threat_score(parsed_data)

        general_result.data = parsed_data
        return general_result

    def get_ip_reputation(self, ip: str) -> APIResult:
        """
        Get IP reputation from OTX

        Args:
            ip: IP address to check

        Returns:
            APIResult with reputation data
        """
        result = self._make_request(
            method="GET",
            endpoint=f"/indicators/IPv4/{ip}/reputation"
        )

        if result.success:
            result.data = self._parse_reputation_response(result.data)

        return result

    def get_ip_geo(self, ip: str) -> APIResult:
        """
        Get geographic information for IP from OTX

        Args:
            ip: IP address to check

        Returns:
            APIResult with geographic data
        """
        return self._make_request(
            method="GET",
            endpoint=f"/indicators/IPv4/{ip}/geo"
        )

    def get_ip_malware(self, ip: str) -> APIResult:
        """
        Get malware samples associated with IP

        Args:
            ip: IP address to check

        Returns:
            APIResult with malware data
        """
        return self._make_request(
            method="GET",
            endpoint=f"/indicators/IPv4/{ip}/malware"
        )

    def get_ip_url_list(self, ip: str) -> APIResult:
        """
        Get URLs associated with the IP

        Args:
            ip: IP address to check

        Returns:
            APIResult with URL list
        """
        return self._make_request(
            method="GET",
            endpoint=f"/indicators/IPv4/{ip}/url_list"
        )

    def get_ip_passive_dns(self, ip: str) -> APIResult:
        """
        Get passive DNS records for IP

        Args:
            ip: IP address to check

        Returns:
            APIResult with passive DNS data
        """
        return self._make_request(
            method="GET",
            endpoint=f"/indicators/IPv4/{ip}/passive_dns"
        )

    def _parse_otx_response(self, ip: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OTX API general endpoint response into standardized format"""

        parsed = {
            "source": "AlienVault OTX",
            "found": False,
            "ip": ip,
            "pulse_count": 0,
            "pulses": [],
            "reputation": 0,
            "country": None,
            "city": None,
            "region": None,
            "continent": None,
            "asn": None,
            "latitude": None,
            "longitude": None,
            "threat_score": 0,
            "tags": [],
            "malware_families": [],
            "attack_ids": [],
            "industries": [],
            "whitelisted": False,
            "validation": [],
            "base_indicator": {},
            "type_title": None,
            "sections": [],
            "passive_dns_count": 0,
            "passive_dns": [],
            "malware_count": 0,
            "malware_samples": [],
            "av_detections": [],
            "url_count": 0,
            "url_list": [],
            "raw_data": raw_data
        }

        # Handle error cases
        if not raw_data or "error" in raw_data:
            return parsed

        # Extract base indicator info (if available)
        if "base_indicator" in raw_data and raw_data["base_indicator"]:
            base = raw_data["base_indicator"]
            parsed["base_indicator"] = base
            parsed["asn"] = base.get("asn")
            parsed["country"] = base.get("country_name")
            parsed["city"] = base.get("city")
            parsed["region"] = base.get("region")
            parsed["continent"] = base.get("continent_code")
            parsed["latitude"] = base.get("latitude")
            parsed["longitude"] = base.get("longitude")
        else:
            # Try to get geo data from root level (fallback)
            parsed["country"] = raw_data.get("country_name")
            parsed["city"] = raw_data.get("city")
            parsed["region"] = raw_data.get("region")
            parsed["continent"] = raw_data.get("continent_code")
            parsed["latitude"] = raw_data.get("latitude")
            parsed["longitude"] = raw_data.get("longitude")
            parsed["asn"] = raw_data.get("asn")

        # Check if indicator is whitelisted
        parsed["whitelisted"] = raw_data.get("whitelisted", False)

        # Get validation info
        parsed["validation"] = raw_data.get("validation", [])

        # Get type title
        parsed["type_title"] = raw_data.get("type_title", "IPv4")

        # Get available sections
        parsed["sections"] = raw_data.get("sections", [])

        # Check if IP is found in any pulses
        pulse_info = raw_data.get("pulse_info", {})

        # Mark as found if we have any data (pulses, geo, or base indicator)
        has_pulses = pulse_info and pulse_info.get("pulses")
        has_geo_data = parsed["country"] or parsed["city"] or parsed["asn"]
        has_base_indicator = parsed["base_indicator"]

        if has_pulses or has_geo_data or has_base_indicator:
            parsed["found"] = True

        # Get pulse count
        parsed["pulse_count"] = pulse_info.get("count", 0) if pulse_info else 0

        # Get pulses
        pulses = pulse_info.get("pulses", []) if pulse_info else []

        # Extract pulse information (threat intelligence reports)
        for pulse in pulses[:15]:  # Get more pulses for better intelligence
            pulse_data = {
                "id": pulse.get("id", ""),
                "name": pulse.get("name", "Unknown"),
                "description": pulse.get("description", "")[:200],  # Truncate long descriptions
                "created": pulse.get("created", ""),
                "modified": pulse.get("modified", ""),
                "author": pulse.get("author_name", "Unknown"),
                "tags": pulse.get("tags", []),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
                "industries": pulse.get("industries", []),
                "tlp": pulse.get("TLP", "white"),
                "references": pulse.get("references", []),
                "adversary": pulse.get("adversary", ""),
                "targeted_countries": pulse.get("targeted_countries", [])
            }
            parsed["pulses"].append(pulse_data)

            # Aggregate tags
            parsed["tags"].extend(pulse.get("tags", []))

            # Aggregate malware families
            # Note: malware_families can be strings or dicts
            if pulse.get("malware_families"):
                for malware in pulse["malware_families"]:
                    if isinstance(malware, dict):
                        parsed["malware_families"].append(malware.get("display_name", malware.get("value", "")))
                    else:
                        parsed["malware_families"].append(str(malware))

            # Aggregate attack IDs (MITRE ATT&CK)
            # Note: attack_ids can be dicts with 'id' and 'name' fields
            if pulse.get("attack_ids"):
                for attack_id in pulse["attack_ids"]:
                    if isinstance(attack_id, dict):
                        parsed["attack_ids"].append(attack_id.get("id", attack_id.get("name", "")))
                    else:
                        parsed["attack_ids"].append(str(attack_id))

            # Aggregate industries
            # Note: industries can be strings or dicts
            if pulse.get("industries"):
                for industry in pulse["industries"]:
                    if isinstance(industry, dict):
                        parsed["industries"].append(industry.get("name", industry.get("id", "")))
                    else:
                        parsed["industries"].append(str(industry))

        # Remove duplicates and sort - filter out empty strings
        parsed["tags"] = sorted(list(set(parsed["tags"])))[:20]  # Limit to top 20 tags
        parsed["malware_families"] = sorted(list(set([m for m in parsed["malware_families"] if m])))
        parsed["attack_ids"] = sorted(list(set([a for a in parsed["attack_ids"] if a])))
        parsed["industries"] = sorted(list(set([i for i in parsed["industries"] if i])))

        # Extract reputation score (if available)
        parsed["reputation"] = raw_data.get("reputation", 0)

        # Calculate threat score based on multiple factors
        threat_score = 0

        # Factor 1: Pulse count (0-50 points)
        if parsed["pulse_count"] > 0:
            threat_score += min(50, parsed["pulse_count"] * 5)

        # Factor 2: Malware families (0-25 points)
        if parsed["malware_families"]:
            threat_score += min(25, len(parsed["malware_families"]) * 5)

        # Factor 3: Attack IDs present (0-25 points)
        if parsed["attack_ids"]:
            threat_score += min(25, len(parsed["attack_ids"]) * 3)

        # Reduce score if whitelisted
        if parsed["whitelisted"]:
            threat_score = max(0, threat_score - 30)

        parsed["threat_score"] = min(100, threat_score)

        return parsed

    def _parse_reputation_response(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OTX reputation response"""
        parsed = {
            "reputation_score": raw_data.get("reputation", 0),
            "threat_score": raw_data.get("threat_score", 0),
            "activities": raw_data.get("activities", []),
            "counts": raw_data.get("counts", {})
        }
        return parsed

    def get_pulse_details(self, pulse_id: str) -> APIResult:
        """
        Get detailed information about a specific pulse

        Args:
            pulse_id: The pulse ID to retrieve

        Returns:
            APIResult with pulse details
        """
        return self._make_request(
            method="GET",
            endpoint=f"/pulses/{pulse_id}"
        )

    def get_subscribed_pulses(self, modified_since: str = None, limit: int = 20) -> APIResult:
        """
        Get pulses the user is subscribed to

        Args:
            modified_since: ISO8601 timestamp to get pulses modified since
            limit: Number of results to return

        Returns:
            APIResult with subscribed pulses
        """
        params = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since

        return self._make_request(
            method="GET",
            endpoint="/pulses/subscribed",
            params=params
        )

    def _calculate_enhanced_threat_score(self, parsed_data: Dict[str, Any]) -> int:
        """
        Calculate enhanced threat score based on all available OTX data

        Args:
            parsed_data: Parsed OTX data with all sections

        Returns:
            Threat score (0-100)
        """
        threat_score = 0

        # Factor 1: Pulse count (0-40 points)
        pulse_count = parsed_data.get("pulse_count", 0)
        if pulse_count > 0:
            threat_score += min(40, pulse_count * 4)

        # Factor 2: Malware/AV detections (0-30 points)
        av_detections = len(parsed_data.get("av_detections", []))
        malware_count = parsed_data.get("malware_count", 0)
        if av_detections > 0:
            threat_score += min(25, av_detections * 2)
        if malware_count > 0:
            threat_score += min(5, malware_count // 100)  # 5 points per 100 samples

        # Factor 3: Malware families (0-15 points)
        malware_families = len(parsed_data.get("malware_families", []))
        if malware_families > 0:
            threat_score += min(15, malware_families * 3)

        # Factor 4: Attack IDs / MITRE ATT&CK (0-10 points)
        attack_ids = len(parsed_data.get("attack_ids", []))
        if attack_ids > 0:
            threat_score += min(10, attack_ids * 2)

        # Factor 5: Suspicious passive DNS activity (0-5 points)
        passive_dns_count = parsed_data.get("passive_dns_count", 0)
        if passive_dns_count > 100:
            threat_score += 5
        elif passive_dns_count > 50:
            threat_score += 3

        # Reduce score if whitelisted
        if parsed_data.get("whitelisted"):
            threat_score = max(0, threat_score - 30)

        return min(100, threat_score)

    def test_connection(self) -> APIResult:
        """Test OTX API connection"""
        # Test with a known IP to verify API key
        return self._make_request(
            method="GET",
            endpoint="/indicators/IPv4/8.8.8.8/general"
        )