import logging
from typing import Dict, Optional
import aiohttp
import asyncio
import json
from datetime import datetime, timedelta

class APIManager:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.session = None
        self.rate_limits = {
            'hibp': {'calls': 0, 'reset_time': None},
            'shodan': {'calls': 0, 'reset_time': None},
            'virustotal': {'calls': 0, 'reset_time': None}
        }

    async def initialize(self):
        """Initialize aiohttp session with proper error handling"""
        try:
            if not self.session:
                timeout = aiohttp.ClientTimeout(total=30)
                self.session = aiohttp.ClientSession(timeout=timeout)
            return self.session
        except Exception as e:
            self.logger.error(f"Failed to initialize API session: {str(e)}", exc_info=True)
            raise

    async def close(self):
        """Safely close the aiohttp session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self.logger.info("API session closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing API session: {str(e)}", exc_info=True)

    async def make_api_request(self, api_name: str, url: str, headers: Optional[Dict] = None,
                             params: Optional[Dict] = None, method: str = 'GET') -> Dict:
        """Make API request with proper error handling and rate limiting"""
        try:
            if not self.session:
                await self.initialize()

            # Check rate limits
            if not self._check_rate_limit(api_name):
                raise Exception(f"Rate limit exceeded for {api_name}")

            async with self.session.request(method, url, headers=headers, params=params) as response:
                if response.status == 401:
                    self.logger.error(f"{api_name} API authentication failed. Check your API key.")
                    raise Exception(f"{api_name} API authentication failed")
                elif response.status == 403:
                    self.logger.error(f"{api_name} API access forbidden. Verify API key permissions.")
                    raise Exception(f"{api_name} API access forbidden")
                elif response.status == 429:
                    self.logger.warning(f"{api_name} API rate limit reached. Implementing backoff...")
                    retry_after = int(response.headers.get('Retry-After', 60))
                    await asyncio.sleep(retry_after)
                    return await self.make_api_request(api_name, url, headers, params, method)
                elif response.status != 200:
                    self.logger.error(f"{api_name} API error: {response.status}")
                    raise Exception(f"{api_name} API error: {response.status}")

                return await response.json()

        except aiohttp.ClientError as e:
            self.logger.error(f"{api_name} API request failed: {str(e)}", exc_info=True)
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in {api_name} API request: {str(e)}", exc_info=True)
            raise

    def _check_rate_limit(self, api_name: str) -> bool:
        """Check and update rate limits"""
        # Implement rate limiting logic here
        return True