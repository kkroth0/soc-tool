"""
Threat Scoring Utilities
Centralized threat scoring logic to avoid duplication
"""

from typing import Dict, Any


class ThreatScorer:
    """Centralized threat scoring logic"""

    @staticmethod
    def calculate_ip_threat_score(data: Dict[str, Any]) -> int:
        """
        Calculate composite threat score from all sources

        Args:
            data: Analysis data from all sources

        Returns:
            Threat score (0-100)
        """
        score = 0

        # VirusTotal scoring (max 60 points)
        if 'virustotal' in data and data['virustotal'].get('found'):
            vt = data['virustotal']
            malicious = vt.get('malicious', 0)
            suspicious = vt.get('suspicious', 0)

            # Weight malicious detections heavily
            score += min(40, malicious * 4)
            # Weight suspicious detections moderately
            score += min(20, suspicious * 2)

            # Bonus for high reputation penalty
            reputation = vt.get('reputation', 0)
            if reputation < -50:
                score += 10

        # AbuseIPDB scoring (max 25 points)
        if 'abuseipdb' in data and data['abuseipdb'].get('found'):
            abuse = data['abuseipdb']
            confidence = abuse.get('confidence_score', 0)
            score += min(25, int(confidence * 0.25))

        # GreyNoise scoring (max 20 points)
        if 'greynoise' in data and data['greynoise'].get('found'):
            gn = data['greynoise']
            if gn.get('malicious'):
                score += 20
            elif gn.get('classification') == 'suspicious':
                score += 10
            elif gn.get('classification') == 'unknown':
                score += 5

        # ThreatFox scoring (max 30 points)
        if 'threatfox' in data and data['threatfox'].get('found'):
            tf = data['threatfox']
            ioc_count = tf.get('ioc_count', 0)
            score += min(30, ioc_count * 5)

        # AlienVault OTX scoring (max 25 points)
        if 'otx' in data and data['otx'].get('found'):
            otx = data['otx']
            pulse_count = otx.get('pulse_count', 0)
            threat_score = otx.get('threat_score', 0)

            # Weight by pulse count
            score += min(15, pulse_count * 2)

            # Add bonus for high OTX threat score
            if threat_score > 70:
                score += 10
            elif threat_score > 30:
                score += 5

        return min(100, score)

    @staticmethod
    def get_threat_level(threat_score: int) -> str:
        """
        Get threat level classification from score

        Args:
            threat_score: Numerical threat score (0-100)

        Returns:
            Threat level string
        """
        if threat_score >= 70:
            return "HIGH RISK"
        elif threat_score >= 30:
            return "MEDIUM RISK"
        else:
            return "LOW RISK"

    @staticmethod
    def get_threat_color(threat_score: int) -> str:
        """
        Get color for threat level display

        Args:
            threat_score: Numerical threat score (0-100)

        Returns:
            Color string for rich display
        """
        if threat_score >= 70:
            return "red"
        elif threat_score >= 30:
            return "yellow"
        else:
            return "green"

    @staticmethod
    def extract_key_findings(data: Dict[str, Any]) -> str:
        """
        Extract key findings for summary display

        Args:
            data: Analysis data from all sources

        Returns:
            Formatted key findings string
        """
        findings = []

        # VirusTotal findings
        if 'virustotal' in data and data['virustotal'].get('malicious', 0) > 0:
            vt = data['virustotal']
            findings.append(f"VT: {vt['malicious']}/{vt.get('total_engines', 0)} detections")

        # AbuseIPDB findings
        if 'abuseipdb' in data and data['abuseipdb'].get('confidence_score', 0) > 0:
            abuse = data['abuseipdb']
            findings.append(f"Abuse: {abuse['confidence_score']}% confidence")

        # GreyNoise findings
        if 'greynoise' in data and data['greynoise'].get('found'):
            gn = data['greynoise']
            if gn.get('malicious'):
                findings.append("GN: Malicious")
            elif gn.get('classification') == 'suspicious':
                findings.append("GN: Suspicious")

        # ThreatFox findings
        if 'threatfox' in data and data['threatfox'].get('ioc_count', 0) > 0:
            tf = data['threatfox']
            findings.append(f"TF: {tf['ioc_count']} IOCs")

        # AlienVault OTX findings
        if 'otx' in data and data['otx'].get('pulse_count', 0) > 0:
            otx = data['otx']
            findings.append(f"OTX: {otx['pulse_count']} pulses")
            if otx.get('malware_families'):
                findings.append(f"Malware: {', '.join(otx['malware_families'][:2])}")

        return "; ".join(findings) if findings else "No threats detected"

    @staticmethod
    def calculate_threat_statistics(results: Dict[str, Any]) -> Dict[str, int]:
        """
        Calculate overall threat statistics for multiple IPs

        Args:
            results: Dictionary of IP analysis results

        Returns:
            Dictionary with threat level counts
        """
        stats = {"high_risk": 0, "medium_risk": 0, "low_risk": 0}

        for result in results.values():
            # Handle both AnalysisResult objects and plain dictionaries
            data = result.data if hasattr(result, 'data') else result

            if not (hasattr(result, 'success') and result.success):
                continue

            threat_score = ThreatScorer.calculate_ip_threat_score(data)

            if threat_score >= 70:
                stats["high_risk"] += 1
            elif threat_score >= 30:
                stats["medium_risk"] += 1
            else:
                stats["low_risk"] += 1

        return stats