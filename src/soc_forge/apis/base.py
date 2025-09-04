"""
Base API Client
Common functionality for all threat intelligence APIs
"""

import requests
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
import logging


@dataclass
class APIResult:
    """Standard result format for all API responses"""
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    rate_limited: bool = False
    response_time_ms: int = 0


class BaseAPIClient(ABC):
    """Base class for all API clients"""
    
    def __init__(self, api_key: str, base_url: str, name: str):
        self.api_key = api_key
        self.base_url = base_url
        self.name = name
        self.session = requests.Session()
        self.logger = logging.getLogger(f"soc_forge.apis.{name}")
        
        # Default headers
        self.session.headers.update({
            'User-Agent': 'SOC-Forge/2.0.0',
            'Accept': 'application/json',
        })
        
    def _make_request(self, method: str, endpoint: str, 
                     headers: Optional[Dict] = None,
                     params: Optional[Dict] = None,
                     json_data: Optional[Dict] = None,
                     timeout: int = 30) -> APIResult:
        """Make API request with error handling and timing"""
        
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Merge headers
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
            
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                params=params,
                json=json_data,
                timeout=timeout
            )
            
            response_time_ms = int((time.time() - start_time) * 1000)
            
            # Handle rate limiting
            if response.status_code == 429:
                return APIResult(
                    success=False,
                    data={},
                    error="Rate limit exceeded",
                    rate_limited=True,
                    response_time_ms=response_time_ms
                )
            
            # Handle other HTTP errors
            if not response.ok:
                return APIResult(
                    success=False,
                    data={},
                    error=f"HTTP {response.status_code}: {response.text}",
                    response_time_ms=response_time_ms
                )
            
            # Parse JSON response
            try:
                data = response.json()
            except ValueError:
                data = {"raw_response": response.text}
            
            return APIResult(
                success=True,
                data=data,
                response_time_ms=response_time_ms
            )
            
        except requests.exceptions.Timeout:
            return APIResult(
                success=False,
                data={},
                error="Request timeout",
                response_time_ms=int((time.time() - start_time) * 1000)
            )
        except requests.exceptions.RequestException as e:
            return APIResult(
                success=False,
                data={},
                error=f"Request failed: {str(e)}",
                response_time_ms=int((time.time() - start_time) * 1000)
            )
    
    @abstractmethod
    def check_ip(self, ip: str) -> APIResult:
        """Check IP against the threat intelligence source"""
        pass
    
    def test_connection(self) -> APIResult:
        """Test API connection and credentials"""
        try:
            # Most APIs have a simple endpoint to test connectivity
            return self._make_request("GET", "")
        except Exception as e:
            return APIResult(
                success=False,
                data={},
                error=f"Connection test failed: {str(e)}"
            )
    
    def get_quota_info(self) -> APIResult:
        """Get API quota information if available"""
        # Override in subclasses if the API provides quota info
        return APIResult(
            success=False,
            data={},
            error="Quota information not available for this API"
        )