import asyncio
import logging
from typing import Dict, Optional, List
from api_manager import APIManager


class APIGatherer:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.api_manager = APIManager(config)

    async def initialize(self):
        """Initialize API connections"""
        try:
            await self.api_manager.initialize()
            self.logger.info("API Gatherer initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize API Gatherer: {str(e)}", exc_info=True)
            raise

    async def gather_all_data(self, target_info: Dict) -> Dict:
        """Gather data from all API sources"""
        results = {
            "hibp_results": {},
            "shodan_results": {},
            "virustotal_results": {},
            "securitytrails_results": {},
            "errors": []
        }

        try:
            # Gather data from different APIs concurrently
            tasks = [
                self.check_hibp(target_info.get("emails", [])),
                self.check_shodan(target_info.get("ips", [])),
                self.check_virustotal(target_info),
                self.check_securitytrails(target_info.get("domains", []))
            ]

            completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for task_result in completed_tasks:
                if isinstance(task_result, Exception):
                    self.logger.error(f"API task failed: {str(task_result)}")
                    results["errors"].append(str(task_result))
                else:
                    results.update(task_result)

            return results

        except Exception as e:
            self.logger.error(f"Error gathering API data: {str(e)}", exc_info=True)
            raise

    async def check_hibp(self, emails: List[str]) -> Dict:
        """Check Have I Been Pwned for email breaches"""
        results = {}

        for email in emails:
            try:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {
                    "hibp-api-key": self.config["api_keys"]["hibp"],
                    "user-agent": "SpyEye Investigation Tool"
                }

                response = await self.api_manager.make_api_request(
                    api_name="hibp",
                    url=url,
                    headers=headers
                )

                results[email] = response
                self.logger.info(f"Successfully checked HIBP for {email}")

                # Respect rate limiting
                await asyncio.sleep(1.5)  # HIBP rate limit

            except Exception as e:
                self.logger.error(f"HIBP check failed for {email}: {str(e)}")
                results[email] = {"error": str(e)}

        return {"hibp_results": results}

    async def check_shodan(self, ips: List[str]) -> Dict:
        """Query Shodan for IP information"""
        results = {}

        for ip in ips:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}"
                params = {"key": self.config["api_keys"]["shodan"]}

                response = await self.api_manager.make_api_request(
                    api_name="shodan",
                    url=url,
                    params=params
                )

                results[ip] = response
                self.logger.info(f"Successfully checked Shodan for {ip}")

            except Exception as e:
                self.logger.error(f"Shodan check failed for {ip}: {str(e)}")
                results[ip] = {"error": str(e)}

        return {"shodan_results": results}

    async def check_virustotal(self, target_info: Dict) -> Dict:
        """Query VirusTotal for various indicators"""
        results = {}

        try:
            headers = {
                "x-apikey": self.config["api_keys"]["virustotal"],
                "accept": "application/json"
            }

            # Check domains
            for domain in target_info.get("domains", []):
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                response = await self.api_manager.make_api_request(
                    api_name="virustotal",
                    url=url,
                    headers=headers
                )
                results[f"domain_{domain}"] = response

            # Check IPs
            for ip in target_info.get("ips", []):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                response = await self.api_manager.make_api_request(
                    api_name="virustotal",
                    url=url,
                    headers=headers
                )
                results[f"ip_{ip}"] = response

            # Respect rate limiting
            await asyncio.sleep(15)  # VT rate limit

        except Exception as e:
            self.logger.error(f"VirusTotal check failed: {str(e)}")
            results["error"] = str(e)

        return {"virustotal_results": results}

    async def check_securitytrails(self, domains: List[str]) -> Dict:
        """Query SecurityTrails for domain information"""
        results = {}

        for domain in domains:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{domain}"
                headers = {"apikey": self.config["api_keys"]["securitytrails"]}

                response = await self.api_manager.make_api_request(
                    api_name="securitytrails",
                    url=url,
                    headers=headers
                )

                results[domain] = response
                self.logger.info(f"Successfully checked SecurityTrails for {domain}")

            except Exception as e:
                self.logger.error(f"SecurityTrails check failed for {domain}: {str(e)}")
                results[domain] = {"error": str(e)}

        return {"securitytrails_results": results}

    async def close(self):
        """Clean up API connections"""
        try:
            await self.api_manager.close()
            self.logger.info("API Gatherer closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing API Gatherer: {str(e)}", exc_info=True)