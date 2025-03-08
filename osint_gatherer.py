import logging
from typing import Dict, List, Optional
from selenium_manager import SeleniumManager
from bs4 import BeautifulSoup
import asyncio
import aiohttp
import whois
import dns.resolver
import time
from urllib.parse import urlparse
import re


class OSINTGatherer:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.selenium_manager = SeleniumManager(use_tor=config.get('use_tor', True))
        self.driver = None
        self.session = None

    async def initialize(self):
        """Initialize OSINT gathering resources"""
        try:
            # Initialize Selenium
            self.driver = self.selenium_manager.initialize_driver()

            # Initialize aiohttp session
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)

            self.logger.info("OSINT Gatherer initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize OSINT Gatherer: {str(e)}", exc_info=True)
            raise

    async def gather_osint_data(self, target_info: Dict) -> Dict:
        """Gather OSINT data from various sources"""
        results = {
            "social_media": {},
            "domain_info": {},
            "email_info": {},
            "google_dorks": [],
            "paste_sites": [],
            "metadata": {},
            "errors": []
        }

        try:
            # Run searches concurrently
            tasks = [
                self.search_google_dorks(target_info),
                self.check_social_networks(target_info),
                self.search_paste_sites(target_info),
                self.gather_domain_info(target_info.get("domains", [])),
                self.gather_email_info(target_info.get("emails", [])),
                self.search_metadata(target_info)
            ]

            completed = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for result in completed:
                if isinstance(result, Exception):
                    self.logger.error(f"OSINT task failed: {str(result)}")
                    results["errors"].append(str(result))
                else:
                    results.update(result)

            return results

        except Exception as e:
            self.logger.error(f"Error gathering OSINT data: {str(e)}", exc_info=True)
            raise

    async def search_google_dorks(self, target_info: Dict) -> Dict:
        """Search using Google dorks"""
        results = []
        dorks = [
            'site:{domain} filetype:pdf',
            'site:{domain} filetype:doc',
            'site:{domain} password',
            'intext:{email} filetype:xlsx',
            'inurl:{domain} login',
            'site:{domain} intext:password',
            'site:{domain} intext:username',
            'site:{domain} intext:config'
        ]

        try:
            for domain in target_info.get("domains", []):
                for dork in dorks:
                    try:
                        query = dork.format(domain=domain)
                        self.driver.get(f"https://www.google.com/search?q={query}")
                        await asyncio.sleep(2)  # Avoid rate limiting

                        soup = BeautifulSoup(self.driver.page_source, 'html.parser')
                        search_results = soup.find_all('div', class_='g')

                        for result in search_results:
                            link = result.find('a')
                            if link:
                                results.append({
                                    "dork": dork,
                                    "url": link['href'],
                                    "title": link.text,
                                    "snippet": result.find('div', class_='VwiC3b').text if result.find('div',
                                                                                                       class_='VwiC3b') else ""
                                })

                    except Exception as e:
                        self.logger.error(f"Error in Google search: {str(e)}", exc_info=True)

            return {"google_dorks": results}

        except Exception as e:
            self.logger.error(f"Google dorks search failed: {str(e)}", exc_info=True)
            return {"google_dorks": [], "error": str(e)}

    async def check_social_networks(self, target_info: Dict) -> Dict:
        """Check various social networks for presence"""
        social_networks = {
            'twitter.com': '/{}',
            'linkedin.com/in': '/{}',
            'facebook.com': '/{}',
            'github.com': '/{}',
            'instagram.com': '/{}',
            'reddit.com/user': '/{}'
        }

        results = {}

        for username in target_info.get("usernames", []):
            results[username] = {}

            for network, path_template in social_networks.items():
                try:
                    url = f"https://{network}{path_template.format(username)}"
                    async with self.session.get(url) as response:
                        results[username][network] = {
                            "exists": response.status == 200,
                            "url": url if response.status == 200 else None
                        }

                except Exception as e:
                    self.logger.error(f"Error checking {network} for {username}: {str(e)}")
                    results[username][network] = {"error": str(e)}

                await asyncio.sleep(1)  # Rate limiting

        return {"social_media": results}

    async def search_paste_sites(self, target_info: Dict) -> Dict:
        """Search paste sites for leaked information"""
        paste_sites = [
            "pastebin.com",
            "ghostbin.com",
            "paste.ee"
        ]

        results = []

        for site in paste_sites:
            try:
                # Use Selenium for JavaScript-heavy sites
                self.driver.get(f"https://{site}")

                # Search for each type of target info
                for email in target_info.get("emails", []):
                    try:
                        search_box = self.driver.find_element_by_name("q")
                        search_box.send_keys(email)
                        search_box.submit()
                        await asyncio.sleep(2)

                        soup = BeautifulSoup(self.driver.page_source, 'html.parser')
                        paste_results = soup.find_all('div', class_='paste-row')

                        for paste in paste_results:
                            results.append({
                                "site": site,
                                "title": paste.find('a').text if paste.find('a') else "Unknown",
                                "url": paste.find('a')['href'] if paste.find('a') else None,
                                "date": paste.find('span', class_='date').text if paste.find('span',
                                                                                             class_='date') else "Unknown",
                                "matched_term": email
                            })

                    except Exception as e:
                        self.logger.error(f"Error searching paste site {site}: {str(e)}")

            except Exception as e:
                self.logger.error(f"Error accessing paste site {site}: {str(e)}")

        return {"paste_sites": results}

    async def gather_domain_info(self, domains: List[str]) -> Dict:
        """Gather detailed information about domains"""
        results = {}

        for domain in domains:
            try:
                # WHOIS information
                whois_info = whois.whois(domain)

                # DNS records
                dns_info = {
                    "a_records": [],
                    "mx_records": [],
                    "ns_records": [],
                    "txt_records": []
                }

                for record_type in ["A", "MX", "NS", "TXT"]:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        dns_info[f"{record_type.lower()}_records"] = [str(rdata) for rdata in answers]
                    except Exception as e:
                        self.logger.error(f"Error getting {record_type} records for {domain}: {str(e)}")

                results[domain] = {
                    "whois": whois_info,
                    "dns": dns_info,
                    "ssl_info": await self._get_ssl_info(domain)
                }

            except Exception as e:
                self.logger.error(f"Error gathering domain info for {domain}: {str(e)}")
                results[domain] = {"error": str(e)}

        return {"domain_info": results}

    async def _get_ssl_info(self, domain: str) -> Dict:
        """Get SSL certificate information"""
        try:
            url = f"https://{domain}"
            async with self.session.get(url) as response:
                return {
                    "issuer": response.headers.get("issuer", "Unknown"),
                    "expires": response.headers.get("expires", "Unknown"),
                    "protocol": response.headers.get("protocol", "Unknown")
                }
        except Exception as e:
            self.logger.error(f"Error getting SSL info for {domain}: {str(e)}")
            return {"error": str(e)}

    async def search_metadata(self, target_info: Dict) -> Dict:
        """Search for metadata in documents and images"""
        results = {
            "documents": [],
            "images": [],
            "errors": []
        }

        # Implementation for metadata extraction
        # This would involve downloading and analyzing files
        # For brevity, this is a placeholder

        return {"metadata": results}

    async def cleanup(self):
        """Clean up resources"""
        try:
            if self.driver:
                self.selenium_manager.quit()

            if self.session and not self.session.closed:
                await self.session.close()

            self.logger.info("OSINT Gatherer cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Error cleaning up OSINT Gatherer: {str(e)}", exc_info=True)