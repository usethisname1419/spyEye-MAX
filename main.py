#!/usr/bin/env python3

import asyncio
import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import logging
from colorama import Fore, Style, init
from tqdm import tqdm
import time

# Import all our modules
from api_integrations import APIIntegrator
from osint_gatherer import OSINTGatherer
from dark_web_monitor import DarkWebMonitor
from intel_x import IntelXSearcher
from onion_sites import OnionSites
from fraud_scorer import FraudScorer
from illegal_activity import IllegalActivityDetector

# Initialize colorama
init()


class Investigation:
    def __init__(self, config_path: str = "config.json"):
        """Initialize all investigation components"""
        self.config = self._load_config(config_path)
        self.setup_logging()
        self.results = {
            "api_results": {},
            "osint_results": {},
            "dark_web_results": {},
            "intelx_results": {},
            "metadata": {
                "start_time": datetime.now().isoformat(),
                "target_info": None
            }
        }

        # Initialize all components
        self.api_integrator = APIIntegrator(self.config)
        self.osint_gatherer = OSINTGatherer(self.config)
        self.dark_web_monitor = DarkWebMonitor(self.config)
        self.intelx_searcher = IntelXSearcher(self.config)

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file not found at {config_path}")
            sys.exit(1)
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON in configuration file {config_path}")
            sys.exit(1)

    def setup_logging(self):
        """Configure logging settings"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
                logging.StreamHandler()
            ]
        )

    async def investigate(self, target_info: Dict) -> Dict:
        """Run comprehensive investigation using all components"""
        self.results["metadata"]["target_info"] = target_info

        # Create progress bar with correct total (4 steps)
        total_steps = 4  # Fraud, API, OSINT, Dark Web
        pbar = tqdm(total=total_steps, desc="Investigation Progress")

        try:
            # Step 1: Fraud Score Analysis
            logging.info("Calculating fraud scores...")
            fraud_scorer = FraudScorer(self.config)
            self.results["fraud_scores"] = await fraud_scorer.calculate_fraud_scores(target_info)
            pbar.update(1)

            # Step 2: API-based investigations
            logging.info("Starting API-based investigation...")
            self.results["api_results"] = await self.api_integrator.comprehensive_search(target_info)
            pbar.update(1)

            # Step 3: OSINT gathering
            logging.info("Starting OSINT gathering...")
            try:
                osint_tasks = [
                    self.osint_gatherer.search_google_dorks(target_info),
                    self.osint_gatherer.search_paste_sites(target_info)
                ]

                if 'emails' in target_info:
                    domains = list(set(email.split('@')[1] for email in target_info['emails']))
                    for domain in domains:
                        osint_tasks.append(self.osint_gatherer.gather_domain_info(domain))

                osint_results = await asyncio.gather(*osint_tasks, return_exceptions=True)

                # Process results, handling any exceptions
                self.results["osint_results"] = {
                    "google_dorks": osint_results[0] if not isinstance(osint_results[0], Exception) else {},
                    "paste_sites": osint_results[1] if not isinstance(osint_results[1], Exception) else {},
                    "domain_info": {}
                }

                # Process domain results if any
                if len(osint_results) > 2:
                    domain_results = {}
                    for i, domain in enumerate(domains):
                        result = osint_results[i + 2]
                        domain_results[domain] = result if not isinstance(result, Exception) else {}
                    self.results["osint_results"]["domain_info"] = domain_results

            except Exception as e:
                logging.error(f"Error in OSINT gathering: {e}")
                self.results["osint_results"] = {"error": str(e)}
            finally:
                pbar.update(1)
            # Step 4: Dark Web Investigation
            logging.info("Starting dark web investigation...")
            try:
                self.results["dark_web_results"] = await self.dark_web_monitor.comprehensive_search(target_info)
            except Exception as e:
                logging.error(f"Error in dark web investigation: {e}")
                self.results["dark_web_results"] = {"error": str(e)}
            finally:
                pbar.update(1)

            # Analyze illegal activities
            logging.info("Analyzing for illegal activities...")
            illegal_activity_detector = IllegalActivityDetector(self.config)
            self.results["illegal_activities"] = await illegal_activity_detector.analyze_data(self.results)

            # Add completion timestamp
            self.results["metadata"]["end_time"] = datetime.now().isoformat()

        except Exception as e:
            logging.error(f"Investigation error: {e}")
            self.results["error"] = str(e)
        finally:
            pbar.close()

        return self.results

    async def cleanup(self):
        """Clean up resources"""
        cleanup_tasks = []

        if hasattr(self, 'dark_web_monitor'):
            cleanup_tasks.append(self.dark_web_monitor.close())

        if hasattr(self, 'osint_gatherer'):
            cleanup_tasks.append(asyncio.create_task(
                asyncio.to_thread(self.osint_gatherer.cleanup)
            ))

        if hasattr(self, 'api_integrator'):
            cleanup_tasks.append(self.api_integrator.close())

        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)

    def analyze_correlations(self, results: Dict) -> Dict:
        """Analyze correlations between accounts and data points"""
        correlations = {
            "email_connections": {},
            "username_connections": {},
            "platform_presence": {},
            "potential_aliases": [],
            "linked_accounts": {},
            "common_patterns": {},
            "timeline": []
        }

        # Analyze email connections
        for email in self.results["metadata"]["target_info"].get("emails", []):
            correlations["email_connections"][email] = {
                "linked_platforms": [],
                "found_in_breaches": [],
                "associated_usernames": [],
                "associated_names": [],
                "social_media": [],
                "dating_sites": [],
                "dark_web_mentions": []
            }

            # Check API results
            if "hibp_results" in self.results["api_results"]:
                breaches = self.results["api_results"]["hibp_results"].get(email, [])
                correlations["email_connections"][email]["found_in_breaches"] = breaches

            # Check social media results
            if "social_media_results" in self.results["api_results"]:
                social = self.results["api_results"]["social_media_results"]
                for platform, data in social.items():
                    if email.lower() in str(data).lower():
                        correlations["email_connections"][email]["linked_platforms"].append(platform)

            # Check dark web mentions
            if "dark_web_results" in self.results:
                for category, entries in self.results["dark_web_results"].items():
                    for entry in entries:
                        if email.lower() in str(entry).lower():
                            correlations["email_connections"][email]["dark_web_mentions"].append({
                                "source": category,
                                "context": str(entry)[:100] + "..."
                            })

        # Analyze username connections
        for username in self.results["metadata"]["target_info"].get("usernames", []):
            correlations["username_connections"][username] = {
                "platforms_found": [],
                "similar_usernames": [],
                "associated_emails": [],
                "dark_web_mentions": [],
                "dating_sites": [],
                "forums": []
            }

            # Check social media presence
            if "social_media_results" in self.results["osint_results"]:
                for platform, data in self.results["osint_results"]["social_media_results"].items():
                    if data.get("exists"):
                        correlations["username_connections"][username]["platforms_found"].append(platform)

            # Check dark web mentions
            if "dark_web_results" in self.results:
                for category, entries in self.results["dark_web_results"].items():
                    for entry in entries:
                        if username.lower() in str(entry).lower():
                            correlations["username_connections"][username]["dark_web_mentions"].append({
                                "source": category,
                                "context": str(entry)[:100] + "..."
                            })

        # Find potential aliases
        usernames = self.results["metadata"]["target_info"].get("usernames", [])
        for i, username1 in enumerate(usernames):
            for username2 in usernames[i + 1:]:
                similarity = self._calculate_username_similarity(username1, username2)
                if similarity > 0.6:  # 60% similarity threshold
                    correlations["potential_aliases"].append({
                        "username1": username1,
                        "username2": username2,
                        "similarity": similarity,
                        "reason": self._find_similarity_reason(username1, username2)
                    })

        # Create timeline
        timeline_events = []

        # Add breach events
        if "hibp_results" in self.results["api_results"]:
            for email, breaches in self.results["api_results"]["hibp_results"].items():
                for breach in breaches:
                    timeline_events.append({
                        "date": breach.get("BreachDate"),
                        "type": "breach",
                        "platform": breach.get("Name"),
                        "details": f"Email {email} found in {breach.get('Name')} breach"
                    })

        # Add dark web activity
        if "dark_web_results" in self.results:
            for category, entries in self.results["dark_web_results"].items():
                for entry in entries:
                    if "date" in entry:
                        timeline_events.append({
                            "date": entry["date"],
                            "type": "dark_web",
                            "platform": category,
                            "details": str(entry.get("preview", ""))[:100] + "..."
                        })

        # Sort timeline by date
        timeline_events.sort(key=lambda x: x["date"] if x.get("date") else "0000-00-00")
        correlations["timeline"] = timeline_events

        return correlations

    def _calculate_username_similarity(self, username1: str, username2: str) -> float:
        """Calculate similarity between two usernames"""
        # Convert to lowercase for comparison
        u1, u2 = username1.lower(), username2.lower()

        # Calculate Levenshtein distance
        distance = self._levenshtein_distance(u1, u2)
        max_length = max(len(u1), len(u2))

        # Return similarity score (1 - normalized distance)
        return 1 - (distance / max_length)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _find_similarity_reason(self, username1: str, username2: str) -> str:
        """Find the reason why two usernames are similar"""
        u1, u2 = username1.lower(), username2.lower()

        # Check for common patterns
        if u1 in u2 or u2 in u1:
            return "One username contains the other"

        # Check for number variations
        base1 = ''.join(c for c in u1 if not c.isdigit())
        base2 = ''.join(c for c in u2 if not c.isdigit())
        if base1 == base2:
            return "Same base with different numbers"

        # Check for common prefixes/suffixes
        min_length = min(len(u1), len(u2))
        prefix_length = 0
        while prefix_length < min_length and u1[prefix_length] == u2[prefix_length]:
            prefix_length += 1
        if prefix_length >= 3:
            return f"Common prefix: {u1[:prefix_length]}"

        return "General string similarity"

    def generate_report(self, results: Dict) -> str:
        """Generate a comprehensive investigation report"""
        report = []

        # Executive Summary
        report.append("# Corporate Investigation Report")
        report.append(f"\nGenerated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n## Executive Summary")
        report.append(
            f"Investigation of target completed with a fraud score of {results.get('fraud_score', 'N/A')}.")

        # Metadata
        report.append("\n## Investigation Metadata")
        metadata = results.get("metadata", {})
        report.append(f"- Start Time: {metadata.get('start_time', 'Unknown')}")
        report.append(f"- End Time: {metadata.get('end_time', 'Unknown')}")
        report.append(f"- Duration: {self._calculate_duration(metadata)}")

        # Fraud Analysis
        report.append("\n## Fraud Analysis")
        if "fraud_indicators" in results:
            for indicator, value in results["fraud_indicators"].items():
                report.append(f"- {indicator}: {value}")

        # Illegal Activities
        report.append("\n## Illegal Activities")
        if "illegal_activities" in results:
            for activity in results["illegal_activities"]:
                report.append(f"- {activity['type']}: {activity['description']}")
                report.append(f"  Evidence: {activity['evidence']}")

        # OSINT Findings
        report.append("\n## OSINT Findings")
        if "osint_results" in results:
            osint = results["osint_results"]
            if "social_media" in osint:
                report.append("\n### Social Media Presence")
                for platform, data in osint["social_media"].items():
                    report.append(f"- {platform}: {data}")

            if "domain_info" in osint:
                report.append("\n### Domain Information")
                for domain, info in osint["domain_info"].items():
                    report.append(f"- {domain}")
                    for key, value in info.items():
                        report.append(f"  - {key}: {value}")

        # API Findings
        report.append("\n## API Investigation Results")
        if "api_results" in results:
            api_results = results["api_results"]

            if "hibp_results" in api_results:
                report.append("\n### Have I Been Pwned Results")
                for email, breaches in api_results["hibp_results"].items():
                    report.append(f"\nEmail: {email}")
                    for breach in breaches:
                        report.append(f"- Breach: {breach['Name']}")
                        report.append(f"  Date: {breach['BreachDate']}")
                        report.append(f"  Description: {breach['Description'][:100]}...")

            if "shodan_results" in api_results:
                report.append("\n### Shodan Results")
                for ip, data in api_results["shodan_results"].items():
                    report.append(f"\nIP: {ip}")
                    report.append(f"- Open Ports: {', '.join(map(str, data.get('ports', [])))}")
                    report.append(f"- Vulnerabilities: {len(data.get('vulns', []))}")

        # Dark Web Findings
        report.append("\n## Dark Web Investigation")
        if "dark_web_results" in results:
            for category, entries in results["dark_web_results"].items():
                report.append(f"\n### {category}")
                for entry in entries:
                    report.append(f"- Date: {entry.get('date', 'Unknown')}")
                    report.append(f"  Source: {entry.get('source', 'Unknown')}")
                    report.append(f"  Preview: {str(entry.get('preview', ''))[:100]}...")

        # Correlations
        if "correlations" in results:
            report.append("\n## Correlation Analysis")
            correlations = results["correlations"]

            if "email_connections" in correlations:
                report.append("\n### Email Connections")
                for email, connections in correlations["email_connections"].items():
                    report.append(f"\nEmail: {email}")
                    for connection_type, items in connections.items():
                        if items:
                            report.append(f"- {connection_type}:")
                            for item in items:
                                report.append(f"  - {item}")

            if "timeline" in correlations:
                report.append("\n### Investigation Timeline")
                for event in correlations["timeline"]:
                    report.append(f"- {event['date']}: {event['type']} - {event['details']}")

        # Summary Statistics
        report.append("\n## Investigation Summary")
        report.append(f"- Total APIs checked: {len(results.get('api_results', {}))}")
        report.append(f"- Fraud Score: {results.get('fraud_score', 'N/A')}")
        report.append(f"- Illegal Activities Found: {len(results.get('illegal_activities', []))}")
        report.append(f"- OSINT Sources Checked: {len(results.get('osint_results', {}))}")
        report.append(
            f"- Dark Web Matches: {sum(len(entries) for entries in results.get('dark_web_results', {}).values())}")

        return "\n".join(report)

    def _calculate_duration(self, metadata: Dict) -> str:
        """Calculate the duration of the investigation"""
        try:
            start = datetime.fromisoformat(metadata.get('start_time'))
            end = datetime.fromisoformat(metadata.get('end_time'))
            duration = end - start
            return str(duration)
        except (ValueError, TypeError):
            return "Unknown"

async def main():
    """Main function to run the investigation"""
    try:
        # Load configuration
        with open('config.json', 'r') as f:
            config = json.load(f)

        # Load target information
        with open('target.json', 'r') as f:
            target_info = json.load(f)

        # Initialize investigation
        investigation = Investigation(config)

        # Run investigation
        async with investigation:
            results = await investigation.investigate(target_info)

        # Generate and save report
        report = investigation.generate_report(results)
        report_filename = f"reports/investigation_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
        os.makedirs('reports', exist_ok=True)

        with open(report_filename, 'w') as f:
            f.write(report)

        print(f"Investigation complete. Report saved to {report_filename}")

    except Exception as e:
        logging.error(f"Error in main: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())