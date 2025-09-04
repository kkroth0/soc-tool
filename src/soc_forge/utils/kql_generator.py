"""
Kibana Query Language (KQL) Generator
Generate KQL queries for Elasticsearch/Kibana security analytics
"""

from typing import List


class KQLGenerator:
    """Generator for Kibana Query Language queries used in Elasticsearch/Kibana"""
    
    def __init__(self):
        self.timespan_default = "7d"  # Default lookback period
    
    def generate_source_ip_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate KQL query for source IP analysis in Kibana"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Source IP Analysis - Traffic FROM these IPs
# Time range: Last {timespan}

source.ip: ({ip_list})

# Alternative patterns for different log types:
# Network logs
source.ip: ({ip_list}) AND event.category: "network"

# Security logs  
source.ip: ({ip_list}) AND event.category: "authentication"

# DNS logs
source.ip: ({ip_list}) AND dns.question.name: *

# HTTP/Web logs
source.ip: ({ip_list}) AND http.request.method: *

# Process/endpoint logs
source.ip: ({ip_list}) AND event.category: "process"
"""
        return query.strip()
    
    def generate_destination_ip_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate KQL query for destination IP analysis in Kibana"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Destination IP Analysis - Traffic TO these IPs  
# Time range: Last {timespan}

destination.ip: ({ip_list})

# Alternative patterns for different log types:
# Network connections
destination.ip: ({ip_list}) AND event.category: "network"

# HTTP requests to suspicious IPs
destination.ip: ({ip_list}) AND http.request.method: *

# DNS resolutions
dns.resolved_ip: ({ip_list})

# Firewall/network security logs
destination.ip: ({ip_list}) AND event.category: "network" AND event.action: ("allow" OR "deny")

# Proxy/web gateway logs  
destination.ip: ({ip_list}) AND event.dataset: "proxy"
"""
        return query.strip()
    
    def generate_combined_ip_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate KQL query for both source and destination IP analysis"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Combined IP Analysis - Traffic FROM or TO these IPs
# Time range: Last {timespan}

(source.ip: ({ip_list}) OR destination.ip: ({ip_list}))

# Specific use cases:
# Any network activity involving these IPs
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: "network"

# Authentication from/to these IPs  
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: "authentication"

# Web traffic involving these IPs
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (http.request.method: * OR event.category: "web")

# DNS activity
(source.ip: ({ip_list}) OR dns.resolved_ip: ({ip_list})) AND dns.question.name: *
"""
        return query.strip()
    
    def generate_traffic_analysis_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate KQL query for network traffic pattern analysis"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Network Traffic Pattern Analysis
# Time range: Last {timespan}

# High-volume connections involving suspicious IPs
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND network.bytes: >1024

# Outbound connections from suspicious sources
source.ip: ({ip_list}) AND network.direction: "outbound"

# Inbound connections to suspicious destinations  
destination.ip: ({ip_list}) AND network.direction: "inbound"

# Unusual ports or protocols
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (destination.port: (>1024 AND <65535) OR network.protocol: ("tcp" OR "udp"))

# Failed connections
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.outcome: "failure"

# Long duration connections
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND network.duration: >300000
"""
        return query.strip()
    
    def generate_security_events_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate KQL query for security events related to IPs"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Security Events Analysis for Suspicious IPs
# Time range: Last {timespan}

# Failed authentication attempts
source.ip: ({ip_list}) AND event.category: "authentication" AND event.outcome: "failure"

# Successful logins from suspicious IPs
source.ip: ({ip_list}) AND event.category: "authentication" AND event.outcome: "success"

# Intrusion detection alerts
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: "intrusion_detection"

# Malware/endpoint security alerts  
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: "malware"

# Process execution from suspicious IPs
source.ip: ({ip_list}) AND event.category: "process" AND event.action: "started"

# File access/modifications
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND event.category: "file"

# Network security alerts
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (event.category: "network" AND event.severity: ("high" OR "critical"))
"""
        return query.strip()
    
    def generate_threat_hunting_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate comprehensive threat hunting KQL query"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Comprehensive Threat Hunting Query
# Time range: Last {timespan}

# Multi-category threat hunting for suspicious IPs
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND 
(
  event.category: ("authentication" OR "network" OR "process" OR "file" OR "malware" OR "intrusion_detection") OR
  event.action: ("login" OR "logout" OR "process_started" OR "file_create" OR "network_connection") OR
  event.outcome: ("failure" OR "success") OR
  threat.indicator.type: ("ip" OR "domain" OR "url")
)

# Lateral movement indicators
source.ip: ({ip_list}) AND (
  event.category: "authentication" AND event.action: "login" AND event.outcome: "success" OR
  event.category: "process" AND process.name: ("powershell.exe" OR "cmd.exe" OR "wmic.exe" OR "psexec.exe") OR
  network.direction: "internal" AND destination.port: (445 OR 135 OR 139 OR 3389)
)

# Command and control indicators  
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (
  network.direction: "outbound" AND destination.port: (80 OR 443 OR 8080 OR 8443) OR
  dns.question.name: (*tmp* OR *temp* OR *.tk OR *.ml OR *.ga OR *.cf) OR
  http.request.method: "POST" AND http.response.body.bytes: <100
)

# Data exfiltration patterns
source.ip: ({ip_list}) AND (
  network.bytes: >10485760 OR
  (network.direction: "outbound" AND file.extension: ("zip" OR "rar" OR "7z" OR "tar"))
)
"""
        return query.strip()
    
    def generate_dns_analysis_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate DNS-specific KQL query"""
        timespan = timespan or self.timespan_default  
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# DNS Analysis for Suspicious IPs (Port 53)
# Time range: Last {timespan}

# Main DNS query - IPs in source OR destination with DNS traffic
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND destination.port: 53

# Alternative DNS patterns:
# DNS queries FROM suspicious IPs  
source.ip: ({ip_list}) AND (destination.port: 53 OR dns.question.name: *)

# DNS queries TO suspicious DNS servers
destination.ip: ({ip_list}) AND destination.port: 53

# DNS resolutions pointing to suspicious IPs
dns.resolved_ip: ({ip_list})

# Comprehensive DNS traffic analysis
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (
  destination.port: 53 OR 
  source.port: 53 OR
  dns.question.name: * OR
  event.category: "dns"
)

# Suspicious DNS patterns with port 53
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND destination.port: 53 AND (
  dns.question.name: (*tmp* OR *temp* OR *dga* OR *.tk OR *.ml OR *.ga OR *.cf) OR
  dns.question.type: ("TXT" OR "NULL") OR
  dns.response_code: ("NXDOMAIN" OR "REFUSED")
)
"""
        return query.strip()
    
    def generate_web_analysis_query(self, ips: List[str], timespan: str = None) -> str:
        """Generate web/HTTP-specific KQL query"""
        timespan = timespan or self.timespan_default
        ip_list = self._format_ip_list(ips)
        
        query = f"""
# Web/HTTP Analysis for Suspicious IPs  
# Time range: Last {timespan}

# HTTP requests FROM suspicious IPs
source.ip: ({ip_list}) AND http.request.method: *

# HTTP requests TO suspicious IPs  
destination.ip: ({ip_list}) AND http.request.method: *

# Suspicious web activity patterns
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (
  http.request.method: ("POST" OR "PUT") OR
  http.response.status_code: (404 OR 403 OR 500) OR
  url.path: (*admin* OR *login* OR *upload* OR *.php OR *.jsp OR *.asp*) OR
  user_agent.original: (*bot* OR *crawler* OR *scanner* OR *curl* OR *wget*)
)

# Web shells or malicious uploads
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND (
  http.request.method: "POST" AND 
  (url.path: *.php OR url.path: *.jsp OR url.path: *.asp*) AND
  http.request.body.content: (*eval* OR *exec* OR *system* OR *shell*)
)

# Large HTTP responses (possible data exfiltration)
(source.ip: ({ip_list}) OR destination.ip: ({ip_list})) AND http.response.body.bytes: >1048576
"""
        return query.strip()
    
    def _format_ip_list(self, ips: List[str]) -> str:
        """Format IP list for KQL queries using OR syntax"""
        if len(ips) == 1:
            return f'"{ips[0]}"'
        return ' OR '.join(f'"{ip}"' for ip in ips)