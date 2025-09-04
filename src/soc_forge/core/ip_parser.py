"""
IP Parser Module
Handles IP extraction and validation from various formats
"""

import re
from typing import List, Set
from dataclasses import dataclass


@dataclass
class IPParsingResult:
    """Result of IP parsing operation"""
    valid_ips: List[str]
    invalid_entries: List[str]
    private_ips_found: List[str]
    duplicates_removed: int


class IPParser:
    """Advanced IP parser with multiple format support"""
    
    def __init__(self):
        # Regex pattern for IPv4 addresses
        self.ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
    def extract_ips(self, text: str, include_private: bool = False, 
                   include_invalid: bool = False) -> IPParsingResult:
        """
        Extract IPs from text with detailed results
        
        Args:
            text: Input text containing IPs in various formats
            include_private: Include private/internal IPs
            include_invalid: Include invalid IP entries in results
            
        Returns:
            IPParsingResult with detailed parsing information
        """
        if not text or not text.strip():
            return IPParsingResult([], [], [], 0)
        
        valid_ips = []
        invalid_entries = []
        private_ips = []
        original_count = 0
        
        # Normalize separators
        normalized_text = re.sub(r'[,;\t]+', ' ', text)
        
        # Find all potential IPs
        potential_ips = set()
        for line in normalized_text.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Extract IPs using regex
            found_ips = re.findall(self.ip_pattern, line)
            for ip in found_ips:
                potential_ips.add(ip.strip())
                original_count += 1
        
        # Process each unique IP
        for ip in potential_ips:
            if self._is_valid_ip_format(ip):
                if self._is_private_ip(ip):
                    private_ips.append(ip)
                    if include_private:
                        valid_ips.append(ip)
                else:
                    valid_ips.append(ip)
            else:
                if include_invalid:
                    invalid_entries.append(ip)
        
        duplicates_removed = original_count - len(potential_ips)
        
        return IPParsingResult(
            valid_ips=valid_ips,
            invalid_entries=invalid_entries,
            private_ips_found=private_ips,
            duplicates_removed=duplicates_removed
        )
    
    def _is_valid_ip_format(self, ip: str) -> bool:
        """Validate IP format"""
        if not ip or not isinstance(ip, str):
            return False
        
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            octets = [int(part) for part in parts]
            return all(0 <= octet <= 255 for octet in octets)
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/reserved range"""
        try:
            parts = [int(part) for part in ip.split('.')]
            first, second = parts[0], parts[1]
            
            # Private/Reserved ranges
            return (
                first == 0 or                                    # 0.0.0.0/8
                first == 10 or                                   # 10.0.0.0/8
                first == 127 or                                  # 127.0.0.0/8
                (first == 169 and second == 254) or             # 169.254.0.0/16
                (first == 172 and 16 <= second <= 31) or        # 172.16.0.0/12
                (first == 192 and second == 168) or             # 192.168.0.0/16
                first >= 224                                     # Multicast/Reserved
            )
        except (ValueError, IndexError):
            return False
    
    def get_ip_classification(self, ip: str) -> dict:
        """Get detailed classification of an IP"""
        classification = {
            'ip': ip,
            'is_valid': self._is_valid_ip_format(ip),
            'is_private': False,
            'classification': 'invalid',
            'range_description': 'Invalid IP format'
        }
        
        if not classification['is_valid']:
            return classification
        
        classification['is_private'] = self._is_private_ip(ip)
        
        if classification['is_private']:
            classification['classification'] = 'private'
            classification['range_description'] = self._get_private_range_description(ip)
        else:
            classification['classification'] = 'public'
            classification['range_description'] = 'Public IP address'
        
        return classification
    
    def _get_private_range_description(self, ip: str) -> str:
        """Get description of private IP range"""
        try:
            parts = [int(part) for part in ip.split('.')]
            first, second = parts[0], parts[1]
            
            if first == 0:
                return "Current network (0.0.0.0/8)"
            elif first == 10:
                return "Private network (10.0.0.0/8)"
            elif first == 127:
                return "Loopback (127.0.0.0/8)"
            elif first == 169 and second == 254:
                return "Link-local (169.254.0.0/16)"
            elif first == 172 and 16 <= second <= 31:
                return "Private network (172.16.0.0/12)"
            elif first == 192 and second == 168:
                return "Private network (192.168.0.0/16)"
            elif first >= 224:
                return "Multicast/Reserved (224.0.0.0/4+)"
            else:
                return "Private/Reserved range"
        except (ValueError, IndexError):
            return "Unknown range"