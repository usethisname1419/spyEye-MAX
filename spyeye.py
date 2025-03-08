#!/usr/bin/env python3

import logging
import asyncio
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import argparse
from tqdm import tqdm

# Import our modules
from logger_config import setup_logger
from api_gatherer import APIGatherer
from osint_gatherer import OSINTGatherer
from darkweb_monitor import DarkWebMonitor
from intel_x import IntelXClient
from fraud_scorer import FraudScorer
from illegal_activity import IllegalActivityDetector


class SpyEye:
    def __init__(self, config_path: str):
        """Initialize SpyEye investigation tool"""
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)

        # Initialize components
        self.api_gatherer = None
        self.osint_gatherer = None
        self.darkweb_monitor = None
        self.intel_x = None
        self.fraud_scorer = None
        self.illegal_detector = None

        # Investigation results
        self.results = {
            "metadata": {
                "start_time": None,
                "end_time": None,
                "target_info": None,
                "investigation_id": None
            },
            "api_results": {},
            "osint_results": {},
            "dark_web_results": {},
            "intel_x_results": {},
            "fraud_analysis": {},
            "illegal_activities": {},
            "correlations": {},
            "risk_assessment": {},
            "timeline": [],
            "errors": []
        }

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Validate required configuration sections
            required_sections = [
                "api_keys", "proxy_settings", "investigation_settings",
                "output_settings", "monitoring_settings"
            ]

            for section in required_sections:
                if section not in config:
                    raise ValueError(f"Missing required configuration section: {section}")

            return config

        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}", exc_info=True)
            raise

    async def initialize(self):
        """Initialize all components"""
        try:
            # Create necessary directories
            self._create_directories()

            # Initialize all components
            self.api_gatherer = APIGatherer(self.config)
            self.osint_gatherer = OSINTGatherer(self.config)
            self.darkweb_monitor = DarkWebMonitor(self.config)
            self.intel_x = IntelXClient(self.config)
            self.fraud_scorer = FraudScorer(self.config)
            self.illegal_detector = IllegalActivityDetector(self.config)

            # Initialize components concurrently
            initialization_tasks = [
                self.api_gatherer.initialize(),
                self.osint_gatherer.initialize(),
                self.darkweb_monitor.initialize(),
                self.intel_x.initialize(),
                self.fraud_scorer.initialize()
            ]

            await asyncio.gather(*initialization_tasks)
            self.logger.info("All components initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize components: {str(e)}", exc_info=True)
            raise

    def _create_directories(self):
        """Create necessary directories for output"""
        directories = [
            "reports",
            "evidence",
            "logs",
            "cache",
            "exports"
        ]

        for directory in directories:
            Path(directory).mkdir(exist_ok=True)

    async def investigate(self, target_info: Dict) -> Dict:
        """Run comprehensive investigation"""
        try:
            # Set investigation metadata
            self.results["metadata"]["start_time"] = datetime.now().isoformat()
            self.results["metadata"]["target_info"] = target_info
            self.results["metadata"]["investigation_id"] = self._generate_investigation_id()

            # Create progress bar
            total_steps = 6  # Number of main investigation steps
            with tqdm(total=total_steps, desc="Investigation Progress") as pbar:
                # Step 1: Fraud Score Analysis
                self.logger.info("Calculating fraud scores...")
                self.results["fraud_analysis"] = await self.fraud_scorer.calculate_comprehensive_score(target_info)
                pbar.update(1)

                # Step 2: API-based Investigation
                self.logger.info("Starting API-based investigation...")
                self.results["api_results"] = await self.api_gatherer.gather_all_data(target_info)
                pbar.update(1)

                # Step 3: OSINT Gathering
                self.logger.info("Starting OSINT gathering...")
                self.results["osint_results"] = await self.osint_gatherer.gather_osint_data(target_info)
                pbar.update(1)

                # Step 4: Dark Web Investigation
                self.logger.info("Starting dark web investigation...")
                self.results["dark_web_results"] = await self.darkweb_monitor.comprehensive_search(target_info)
                pbar.update(1)

                # Step 5: Intel X Search
                self.logger.info("Starting Intel X search...")
                self.results["intel_x_results"] = await self.intel_x.search(target_info)
                pbar.update(1)

                # Step 6: Analysis and Correlation
                self.logger.info("Analyzing correlations and generating assessment...")
                await self._analyze_and_correlate()
                pbar.update(1)

            # Set completion time
            self.results["metadata"]["end_time"] = datetime.now().isoformat()

            # Generate and save report
            report_path = await self._generate_report()
            self.logger.info(f"Investigation complete. Report saved to: {report_path}")

            return self.results

        except Exception as e:
            self.logger.error(f"Investigation failed: {str(e)}", exc_info=True)
            self.results["errors"].append(str(e))
            raise
        finally:
            # Ensure we clean up resources
            await self._cleanup()

    def _generate_investigation_id(self) -> str:
        """Generate unique investigation ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"INV_{timestamp}"

    async def _analyze_and_correlate(self):
        """Analyze and correlate all gathered data"""
        try:
            correlations = {
                "identity_matches": [],
                "behavioral_patterns": [],
                "network_connections": [],
                "temporal_correlations": [],
                "cross_platform_activities": [],
                "risk_indicators": [],
                "confidence_scores": {}
            }

            # Analyze illegal activities
            illegal_activities = await self.illegal_detector.analyze_data(self.results)
            self.results["illegal_activities"] = illegal_activities

            # Identity Correlation
            correlations["identity_matches"] = self._correlate_identities()

            # Network Analysis
            correlations["network_connections"] = self._analyze_network_connections()

            # Timeline Analysis
            correlations["temporal_correlations"] = self._analyze_temporal_patterns()

            # Cross-platform Activity Analysis
            correlations["cross_platform_activities"] = self._analyze_cross_platform_activities()

            # Calculate confidence scores
            correlations["confidence_scores"] = self._calculate_confidence_scores()

            self.results["correlations"] = correlations

            # Generate risk assessment
            self.results["risk_assessment"] = self._generate_risk_assessment()

        except Exception as e:
            self.logger.error(f"Correlation analysis failed: {str(e)}", exc_info=True)
            raise

    def _correlate_identities(self) -> List[Dict]:
        """Correlate identities across different data sources"""
        identity_matches = []

        try:
            # Extract identifiers from all data sources
            identifiers = self._extract_identifiers()

            # Find connections between identifiers
            for id1 in identifiers:
                for id2 in identifiers:
                    if id1 != id2:
                        confidence = self._calculate_identifier_similarity(id1, id2)
                        if confidence > 0.7:  # 70% confidence threshold
                            identity_matches.append({
                                "identifier1": id1,
                                "identifier2": id2,
                                "confidence": confidence,
                                "evidence": self._gather_correlation_evidence(id1, id2),
                                "source": self._determine_correlation_source(id1, id2)
                            })

            return identity_matches

        except Exception as e:
            self.logger.error(f"Identity correlation failed: {str(e)}", exc_info=True)
            return []

    def _analyze_network_connections(self) -> List[Dict]:
        """Analyze network connections between different entities"""
        connections = []

        try:
            # Analyze API results for network connections
            if "api_results" in self.results:
                connections.extend(self._analyze_api_network_connections())

            # Analyze OSINT data for network connections
            if "osint_results" in self.results:
                connections.extend(self._analyze_osint_network_connections())

            # Analyze dark web connections
            if "dark_web_results" in self.results:
                connections.extend(self._analyze_darkweb_network_connections())

            return connections

        except Exception as e:
            self.logger.error(f"Network connection analysis failed: {str(e)}", exc_info=True)
            return []

    def _analyze_temporal_patterns(self) -> List[Dict]:
        """Analyze temporal patterns across all data"""
        patterns = []

        try:
            # Create timeline of all events
            timeline = self._create_unified_timeline()

            # Analyze temporal clusters
            clusters = self._identify_temporal_clusters(timeline)

            # Analyze activity patterns
            patterns = self._identify_activity_patterns(clusters)

            return patterns

        except Exception as e:
            self.logger.error(f"Temporal pattern analysis failed: {str(e)}", exc_info=True)
            return []

    async def _generate_report(self) -> str:
        """Generate comprehensive investigation report"""
        try:
            report = {
                "executive_summary": self._generate_executive_summary(),
                "investigation_details": self._generate_investigation_details(),
                "findings": self._generate_findings_section(),
                "risk_assessment": self._generate_risk_section(),
                "recommendations": self._generate_recommendations(),
                "technical_details": self._generate_technical_details(),
                "appendices": self._generate_appendices()
            }

            # Save report in multiple formats
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_path = f"reports/investigation_{self.results['metadata']['investigation_id']}"

            # Save JSON format
            json_path = f"{base_path}.json"
            with open(json_path, 'w') as f:
                json.dump(report, f, indent=4)

            # Save HTML report
            html_path = f"{base_path}.html"
            await self._generate_html_report(report, html_path)

            # Save PDF report
            pdf_path = f"{base_path}.pdf"
            await self._generate_pdf_report(report, pdf_path)

            return base_path

        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}", exc_info=True)
            raise

    def _generate_executive_summary(self) -> Dict:
        """Generate executive summary of investigation"""
        return {
            "investigation_id": self.results["metadata"]["investigation_id"],
            "investigation_period": {
                "start": self.results["metadata"]["start_time"],
                "end": self.results["metadata"]["end_time"]
            },
            "risk_level": self.results["risk_assessment"]["overall_risk_level"],
            "key_findings": self._extract_key_findings(),
            "critical_alerts": self._extract_critical_alerts(),
            "recommendation_summary": self._summarize_recommendations()
        }

    def _generate_findings_section(self) -> Dict:
        """Generate detailed findings section"""
        return {
            "identity_findings": self._summarize_identity_findings(),
            "network_analysis": self._summarize_network_analysis(),
            "temporal_analysis": self._summarize_temporal_analysis(),
            "risk_indicators": self._summarize_risk_indicators(),
            "evidence_summary": self._summarize_evidence()
        }

    async def _cleanup(self):
        """Clean up resources"""
        try:
            cleanup_tasks = []

            if self.api_gatherer:
                cleanup_tasks.append(self.api_gatherer.close())
            if self.osint_gatherer:
                cleanup_tasks.append(self.osint_gatherer.cleanup())
            if self.darkweb_monitor:
                cleanup_tasks.append(self.darkweb_monitor.close())
            if self.intel_x:
                cleanup_tasks.append(self.intel_x.close())
            if self.fraud_scorer:
                cleanup_tasks.append(self.fraud_scorer.close())

            await asyncio.gather(*cleanup_tasks)
            self.logger.info("All resources cleaned up successfully")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}", exc_info=True)


def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command line argument parser"""
    parser = argparse.ArgumentParser(
        description="SpyEye - Advanced Corporate Investigation Tool"
    )

    parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to configuration file'
    )

    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Path to target information file'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    return parser


async def main():
    """Main execution function"""
    try:
        # Parse command line arguments
        parser = setup_argument_parser()
        args = parser.parse_args()

        # Setup logging
        log_level = logging.DEBUG if args.debug else logging.INFO
        logger = setup_logger(log_level)

        # Print banner
        print_banner()

        # Load target information
        with open(args.target, 'r') as f:
            target_info = json.load(f)

        # Initialize SpyEye
        spyeye = SpyEye(args.config)
        await spyeye.initialize()

        # Run investigation
        results = await spyeye.investigate(target_info)

        logger.info("Investigation completed successfully")

    except Exception as e:
        logger.error(f"Investigation failed: {str(e)}", exc_info=True)
        raise


def print_banner():
    """Print SpyEye banner"""
    banner = """
╔══════════════════════════════════════════╗
║     SPY EYE v1.0 - LTH Cybersecurity     ║
╚══════════════════════════════════════════╝
    """
    print(banner)


if __name__ == "__main__":
    asyncio.run(main())