# intel_x.py
import logging
from typing import Dict, List, Optional
import aiohttp
import asyncio
from datetime import datetime, timedelta
import json
import time
from urllib.parse import urlencode


class IntelXClient:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.api_key = config.get("api_keys", {}).get("intelx")
        self.base_url = "https://2.intelx.io"
        self.session = None
        self.rate_limits = {
            "search": {"calls": 0, "reset_time": None, "limit": 10},
            "view": {"calls": 0, "reset_time": None, "limit": 50}
        }

    async def initialize(self):
        """Initialize Intel X client"""
        try:
            if not self.api_key:
                raise ValueError("Intel X API key not found in configuration")

            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'x-key': self.api_key,
                    'User-Agent': 'SpyEye-Investigation-Tool/1.0'
                }
            )
            self.logger.info("Intel X client initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Intel X client: {str(e)}", exc_info=True)
            raise

    async def search(self, target_info: Dict) -> Dict:
        """Perform comprehensive Intel X search"""
        results = {
            "search_results": [],
            "analyzed_data": {},
            "statistics": {
                "total_records": 0,
                "categories": {},
                "confidence_levels": {},
                "timestamps": {
                    "start": datetime.now().isoformat(),
                    "end": None
                }
            },
            "errors": []
        }

        try:
            # Generate search terms from target info
            search_terms = self._generate_search_terms(target_info)

            for term in search_terms:
                try:
                    # Check rate limits
                    await self._check_rate_limit("search")

                    # Perform search
                    search_results = await self._search_term(term)

                    if search_results:
                        # Process and analyze results
                        analyzed_results = await self._analyze_results(search_results)

                        results["search_results"].extend(analyzed_results)
                        results["statistics"]["total_records"] += len(analyzed_results)

                        # Update statistics
                        self._update_statistics(results["statistics"], analyzed_results)

                except Exception as e:
                    error_msg = f"Error searching term '{term}': {str(e)}"
                    self.logger.error(error_msg, exc_info=True)
                    results["errors"].append(error_msg)

            results["statistics"]["timestamps"]["end"] = datetime.now().isoformat()
            return results

        except Exception as e:
            self.logger.error(f"Intel X search failed: {str(e)}", exc_info=True)
            raise

    async def _search_term(self, term: str) -> List[Dict]:
        """Execute search for a single term"""
        try:
            # Prepare search parameters
            params = {
                "term": term,
                "maxresults": 100,
                "media": 0,  # All media types
                "sort": 4,  # Sort by date, newest first
                "terminate": [],  # No termination
                "timeout": 0
            }

            async with self.session.post(
                    f"{self.base_url}/intelligent/search",
                    json=params
            ) as response:
                if response.status != 200:
                    raise Exception(f"Search failed with status {response.status}")

                search_data = await response.json()
                search_id = search_data.get("id")

                if not search_id:
                    raise Exception("No search ID received")

                # Wait for results
                results = await self._get_search_results(search_id)
                return results

        except Exception as e:
            self.logger.error(f"Search term execution failed: {str(e)}", exc_info=True)
            raise

    async def _get_search_results(self, search_id: str) -> List[Dict]:
        """Get results for a search ID"""
        try:
            results = []
            offset = 0
            limit = 100

            while True:
                # Check rate limits
                await self._check_rate_limit("view")

                params = {
                    "id": search_id,
                    "limit": limit,
                    "offset": offset
                }

                async with self.session.get(
                        f"{self.base_url}/intelligent/search/result",
                        params=params
                ) as response:
                    if response.status != 200:
                        raise Exception(f"Result fetch failed with status {response.status}")

                    data = await response.json()
                    records = data.get("records", [])

                    if not records:
                        break

                    results.extend(records)
                    offset += limit

                    if len(records) < limit:
                        break

            return results

        except Exception as e:
            self.logger.error(f"Failed to get search results: {str(e)}", exc_info=True)
            raise

    async def _analyze_results(self, results: List[Dict]) -> List[Dict]:
        """Analyze and enrich search results"""
        analyzed_results = []

        for result in results:
            try:
                # Check rate limits
                await self._check_rate_limit("view")

                # Get full content if available
                if result.get("media") == 0:  # Text content
                    content = await self._get_content(result.get("systemid"))
                    result["full_content"] = content

                # Analyze and categorize
                analyzed_result = {
                    "id": result.get("systemid"),
                    "type": result.get("media"),
                    "date": result.get("date"),
                    "title": result.get("name"),
                    "snippet": result.get("snippet"),
                    "full_content": result.get("full_content"),
                    "confidence": self._calculate_confidence(result),
                    "category": self._categorize_result(result),
                    "metadata": {
                        "bucket": result.get("bucket"),
                        "size": result.get("size"),
                        "media": result.get("media"),
                        "added": result.get("added")
                    }
                }

                analyzed_results.append(analyzed_result)

            except Exception as e:
                self.logger.error(f"Failed to analyze result {result.get('systemid')}: {str(e)}")

        return analyzed_results

    async def _get_content(self, system_id: str) -> Optional[str]:
        """Retrieve full content for a result"""
        try:
            params = {
                "systemid": system_id,
                "type": 0  # Raw content
            }

            async with self.session.get(
                    f"{self.base_url}/intelligent/view",
                    params=params
            ) as response:
                if response.status == 200:
                    return await response.text()
                return None

        except Exception as e:
            self.logger.error(f"Failed to get content for {system_id}: {str(e)}")
            return None

    def _generate_search_terms(self, target_info: Dict) -> List[str]:
        """Generate search terms from target information"""
        terms = []

        # Add direct terms
        for key in ["emails", "domains", "usernames", "phone_numbers"]:
            terms.extend(target_info.get(key, []))

        # Add combinations and variations
        for domain in target_info.get("domains", []):
            terms.append(f"site:{domain}")
            terms.append(f"domain:{domain}")

        for email in target_info.get("emails", []):
            username = email.split("@")[0]
            terms.append(username)

        return list(set(terms))  # Remove duplicates

    def _calculate_confidence(self, result: Dict) -> int:
        """Calculate confidence score for a result"""
        confidence = 0

        # Add confidence based on various factors
        if result.get("verified"):
            confidence += 30

        if result.get("date"):
            # Higher confidence for recent results
            date = datetime.strptime(result["date"], "%Y-%m-%d %H:%M:%S")
            if date > datetime.now() - timedelta(days=30):
                confidence += 20
            elif date > datetime.now() - timedelta(days=90):
                confidence += 10

        if result.get("bucket") == "pastes":
            confidence += 15

        return min(confidence, 100)  # Cap at 100

    def _categorize_result(self, result: Dict) -> str:
        """Categorize result based on content and metadata"""
        # Implementation of result categorization
        return "general"

    def _update_statistics(self, statistics: Dict, results: List[Dict]):
        """Update search statistics"""
        for result in results:
            category = result.get("category", "unknown")
            confidence = result.get("confidence", 0)

            statistics["categories"][category] = statistics["categories"].get(category, 0) + 1

            confidence_level = f"{(confidence // 10) * 10}-{((confidence // 10) * 10) + 9}"
            statistics["confidence_levels"][confidence_level] = \
                statistics["confidence_levels"].get(confidence_level, 0) + 1

    async def _check_rate_limit(self, action: str):
        """Check and handle rate limits"""
        rate_limit = self.rate_limits.get(action)

        if not rate_limit:
            return

        current_time = time.time()

        if rate_limit["reset_time"] and current_time < rate_limit["reset_time"]:
            if rate_limit["calls"] >= rate_limit["limit"]:
                wait_time = rate_limit["reset_time"] - current_time
                self.logger.warning(f"Rate limit reached for {action}, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)
                rate_limit["calls"] = 0
                rate_limit["reset_time"] = current_time + 60
        else:
            rate_limit["calls"] = 0
            rate_limit["reset_time"] = current_time + 60

        rate_limit["calls"] += 1

    async def close(self):
        """Clean up resources"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
            self.logger.info("Intel X client closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing Intel X client: {str(e)}", exc_info=True)