# darkweb_monitor.py
import logging
from typing import Dict, List, Optional
import aiohttp
import asyncio
from datetime import datetime
import socks
import socket
from stem import Signal
from stem.control import Controller
import time
import json
from urllib.parse import urljoin


class DarkWebMonitor:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.session = None
        self.tor_controller = None
        self.onion_sites = self._load_onion_sites()
        self.last_ip_change = time.time()

    def _load_onion_sites(self) -> Dict:
        """Load onion sites from configuration"""
        try:
            with open('config/onion_sites.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load onion sites: {str(e)}", exc_info=True)
            return {
                "markets": [],
                "forums": [],
                "paste_sites": [],
                "search_engines": []
            }

    async def initialize(self):
        """Initialize Tor connection and session"""
        try:
            # Configure Tor connection
            await self._setup_tor()

            # Initialize aiohttp session with Tor proxy
            tor_proxy = f"socks5h://127.0.0.1:{self.config.get('tor_socks_port', 9050)}"
            conn = aiohttp.TCPConnector(ssl=False)
            self.session = aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={'User-Agent': self._get_random_user_agent()}
            )

            self.logger.info("Dark Web Monitor initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Dark Web Monitor: {str(e)}", exc_info=True)
            raise

    async def _setup_tor(self):
        """Setup Tor connection with better error handling"""
        try:
            # First check if Tor SOCKS proxy is accessible
            sock = socket.socket()
            try:
                sock.connect(('127.0.0.1', 9050))
                sock.close()
            except Exception as e:
                self.logger.error(f"Tor SOCKS proxy not accessible: {str(e)}")
                raise

            # Try to connect to Tor control port
            try:
                self.tor_controller = Controller.from_port(
                    address='127.0.0.1',
                    port=9051  # Note: Changed from 9050 to 9051 (control port)
                )
            except Exception as e:
                self.logger.error(f"Could not connect to Tor control port: {str(e)}")
                # Try alternative port
                try:
                    self.tor_controller = Controller.from_port(
                        address='127.0.0.1',
                        port=9050
                    )
                except Exception as e2:
                    self.logger.error(f"Could not connect to alternative Tor port: {str(e2)}")
                    raise

            # Try to authenticate
            

            self.logger.info("Tor connection established successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to setup Tor: {str(e)}")
            # Continue without Tor in test mode
            if hasattr(self, 'test_mode') and self.test_mode:
                self.logger.warning("Running in test mode - continuing without Tor")
                return False
            raise

    async def _change_tor_identity(self):
        """Change Tor identity to get new IP"""
        try:
            if time.time() - self.last_ip_change < 10:
                await asyncio.sleep(10)

            self.tor_controller.signal(Signal.NEWNYM)
            self.last_ip_change = time.time()
            await asyncio.sleep(self.config.get('tor_identity_wait', 5))
            self.logger.info("Tor identity changed successfully")
        except Exception as e:
            self.logger.error(f"Failed to change Tor identity: {str(e)}", exc_info=True)

    async def comprehensive_search(self, target_info: Dict) -> Dict:
        """Perform comprehensive dark web search"""
        results = {
            "markets": [],
            "forums": [],
            "paste_sites": [],
            "search_results": [],
            "timestamps": {
                "start": datetime.now().isoformat(),
                "end": None
            }
        }

        try:
            search_tasks = [
                self._search_markets(target_info),
                self._search_forums(target_info),
                self._search_paste_sites(target_info),
                self._search_engines(target_info)
            ]

            completed = await asyncio.gather(*search_tasks, return_exceptions=True)

            for result in completed:
                if isinstance(result, Exception):
                    self.logger.error(f"Dark web search task failed: {str(result)}")
                else:
                    results.update(result)

            results["timestamps"]["end"] = datetime.now().isoformat()
            return results

        except Exception as e:
            self.logger.error(f"Comprehensive dark web search failed: {str(e)}", exc_info=True)
            raise

    async def _search_markets(self, target_info: Dict) -> Dict:
        """Search dark web markets"""
        results = []

        for market in self.onion_sites["markets"]:
            try:
                await self._change_tor_identity()

                async with self.session.get(market["url"]) as response:
                    if response.status == 200:
                        text = await response.text()

                        # Search for various target indicators
                        for email in target_info.get("emails", []):
                            if email in text:
                                results.append({
                                    "site": market["name"],
                                    "url": market["url"],
                                    "type": "email_match",
                                    "matched_term": email,
                                    "timestamp": datetime.now().isoformat()
                                })

                        # Add more search patterns here

            except Exception as e:
                self.logger.error(f"Error searching market {market['name']}: {str(e)}")

        return {"markets": results}

    async def _search_forums(self, target_info: Dict) -> Dict:
        """Search dark web forums"""
        results = []

        for forum in self.onion_sites["forums"]:
            try:
                await self._change_tor_identity()

                # Search forum
                search_url = urljoin(forum["url"], forum.get("search_path", "/search"))

                for term in self._generate_search_terms(target_info):
                    try:
                        async with self.session.post(
                                search_url,
                                data={"q": term},
                                headers=self._get_forum_headers(forum)
                        ) as response:
                            if response.status == 200:
                                text = await response.text()

                                # Process search results
                                results.extend(
                                    self._parse_forum_results(text, forum, term)
                                )

                    except Exception as e:
                        self.logger.error(f"Error searching term '{term}' in forum {forum['name']}: {str(e)}")

            except Exception as e:
                self.logger.error(f"Error accessing forum {forum['name']}: {str(e)}")

        return {"forums": results}

    async def _search_paste_sites(self, target_info: Dict) -> Dict:
        """Search dark web paste sites"""
        results = []

        for site in self.onion_sites["paste_sites"]:
            try:
                await self._change_tor_identity()

                async with self.session.get(site["url"]) as response:
                    if response.status == 200:
                        text = await response.text()

                        # Search for matches
                        matches = self._find_matches_in_text(text, target_info)
                        if matches:
                            results.append({
                                "site": site["name"],
                                "url": site["url"],
                                "matches": matches,
                                "timestamp": datetime.now().isoformat()
                            })

            except Exception as e:
                self.logger.error(f"Error searching paste site {site['name']}: {str(e)}")

        return {"paste_sites": results}

    async def _search_engines(self, target_info: Dict) -> Dict:
        """Search dark web search engines"""
        results = []

        for engine in self.onion_sites["search_engines"]:
            try:
                await self._change_tor_identity()

                for term in self._generate_search_terms(target_info):
                    try:
                        search_url = f"{engine['url']}?q={term}"
                        async with self.session.get(search_url) as response:
                            if response.status == 200:
                                text = await response.text()

                                # Process search results
                                matches = self._parse_search_results(text, engine)
                                if matches:
                                    results.append({
                                        "engine": engine["name"],
                                        "term": term,
                                        "matches": matches,
                                        "timestamp": datetime.now().isoformat()
                                    })

                    except Exception as e:
                        self.logger.error(f"Error searching term '{term}' in engine {engine['name']}: {str(e)}")

            except Exception as e:
                self.logger.error(f"Error accessing search engine {engine['name']}: {str(e)}")

        return {"search_results": results}

    def _generate_search_terms(self, target_info: Dict) -> List[str]:
        """Generate search terms from target info"""
        terms = []

        # Add emails
        terms.extend(target_info.get("emails", []))

        # Add usernames
        terms.extend(target_info.get("usernames", []))

        # Add domains
        terms.extend(target_info.get("domains", []))

        # Add phone numbers
        terms.extend(target_info.get("phone_numbers", []))

        return terms

    def _find_matches_in_text(self, text: str, target_info: Dict) -> List[Dict]:
        """Find matches of target info in text"""
        matches = []

        for key, values in target_info.items():
            if isinstance(values, list):
                for value in values:
                    if value in text:
                        matches.append({
                            "type": key,
                            "value": value,
                            "context": self._get_context(text, value)
                        })

        return matches

    def _get_context(self, text: str, value: str, context_size: int = 100) -> str:
        """Get context around a matched value"""
        try:
            start = max(0, text.find(value) - context_size)
            end = min(len(text), text.find(value) + len(value) + context_size)
            return text[start:end].strip()
        except Exception:
            return ""

    def _get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        # Implementation of user agent rotation
        return "Mozilla/5.0 ..."

    def _get_forum_headers(self, forum: Dict) -> Dict:
        """Get headers for forum requests"""
        return {
            "User-Agent": self._get_random_user_agent(),
            "Referer": forum["url"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

    async def close(self):
        """Clean up resources"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()

            if self.tor_controller:
                self.tor_controller.close()

            self.logger.info("Dark Web Monitor cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Error cleaning up Dark Web Monitor: {str(e)}", exc_info=True)
