# illegal_activity.py
import logging
from typing import Dict, List, Set, Optional
import re
from datetime import datetime
import json
from collections import defaultdict


class IllegalActivityDetector:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.patterns = self._load_patterns()
        self.risk_scores = defaultdict(int)
        self.detected_activities = []

    def _load_patterns(self) -> Dict:
        """Load detection patterns from configuration"""
        try:
            with open('config/illegal_patterns.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load illegal patterns: {str(e)}", exc_info=True)
            return {
                "keywords": {
                    "high_risk": [],
                    "medium_risk": [],
                    "low_risk": []
                },
                "regex_patterns": {},
                "context_rules": []
            }

    async def analyze_data(self, investigation_results: Dict) -> Dict:
        """Analyze data for illegal activities"""
        results = {
            "detected_activities": [],
            "risk_assessment": {
                "overall_risk_score": 0,
                "risk_factors": [],
                "categories": {}
            },
            "timeline": [],
            "indicators": {
                "high_risk": [],
                "medium_risk": [],
                "low_risk": []
            },
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0"
            }
        }

        try:
            # Analyze different data sources
            await self._analyze_dark_web_data(investigation_results.get("dark_web_results", {}), results)
            await self._analyze_osint_data(investigation_results.get("osint_results", {}), results)
            await self._analyze_api_data(investigation_results.get("api_results", {}), results)

            # Calculate final risk score
            results["risk_assessment"]["overall_risk_score"] = self._calculate_overall_risk()

            # Generate timeline
            results["timeline"] = self._generate_activity_timeline()

            return results

        except Exception as e:
            self.logger.error(f"Error in illegal activity analysis: {str(e)}", exc_info=True)
            raise

    async def _analyze_dark_web_data(self, dark_web_results: Dict, results: Dict):
        """Analyze dark web data for illegal activities"""
        try:
            for category, entries in dark_web_results.items():
                for entry in entries:
                    # Check for high-risk keywords
                    for keyword in self.patterns["keywords"]["high_risk"]:
                        if keyword.lower() in str(entry).lower():
                            activity = {
                                "type": "dark_web_high_risk",
                                "category": category,
                                "keyword": keyword,
                                "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                                "source": "dark_web",
                                "risk_level": "high",
                                "context": self._get_context(str(entry), keyword)
                            }
                            results["detected_activities"].append(activity)
                            results["indicators"]["high_risk"].append(activity)
                            self.risk_scores["dark_web"] += 10

                    # Apply regex patterns
                    self._apply_regex_patterns(str(entry), "dark_web", results)

        except Exception as e:
            self.logger.error(f"Error analyzing dark web data: {str(e)}", exc_info=True)

    async def _analyze_osint_data(self, osint_results: Dict, results: Dict):
        """Analyze OSINT data for illegal activities"""
        try:
            # Check social media results
            if "social_media" in osint_results:
                for platform, data in osint_results["social_media"].items():
                    self._analyze_social_media_content(data, platform, results)

            # Check paste sites
            if "paste_sites" in osint_results:
                for paste in osint_results["paste_sites"]:
                    self._analyze_paste_content(paste, results)

        except Exception as e:
            self.logger.error(f"Error analyzing OSINT data: {str(e)}", exc_info=True)

    async def _analyze_api_data(self, api_results: Dict, results: Dict):
        """Analyze API results for illegal activities"""
        try:
            # Check VirusTotal results
            if "virustotal_results" in api_results:
                self._analyze_virustotal_data(api_results["virustotal_results"], results)

            # Check other API results
            if "shodan_results" in api_results:
                self._analyze_shodan_data(api_results["shodan_results"], results)

        except Exception as e:
            self.logger.error(f"Error analyzing API data: {str(e)}", exc_info=True)

    def _analyze_social_media_content(self, data: Dict, platform: str, results: Dict):
        """Analyze social media content for indicators"""
        try:
            content = str(data)

            # Check for suspicious patterns
            for pattern_type, patterns in self.patterns["regex_patterns"].items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        activity = {
                            "type": "social_media_pattern_match",
                            "platform": platform,
                            "pattern_type": pattern_type,
                            "matched_text": match.group(),
                            "context": self._get_context(content, match.group()),
                            "risk_level": "medium",
                            "timestamp": datetime.now().isoformat()
                        }
                        results["detected_activities"].append(activity)
                        results["indicators"]["medium_risk"].append(activity)
                        self.risk_scores["social_media"] += 5

        except Exception as e:
            self.logger.error(f"Error analyzing social media content: {str(e)}", exc_info=True)

    def _analyze_paste_content(self, paste: Dict, results: Dict):
        """Analyze paste site content"""
        try:
            content = paste.get("content", "")

            # Check for sensitive data patterns
            for pattern_name, pattern in self.patterns["regex_patterns"].items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    activity = {
                        "type": "paste_site_pattern_match",
                        "pattern_type": pattern_name,
                        "matched_text": match.group(),
                        "paste_title": paste.get("title"),
                        "risk_level": "medium",
                        "timestamp": paste.get("date", datetime.now().isoformat())
                    }
                    results["detected_activities"].append(activity)
                    results["indicators"]["medium_risk"].append(activity)
                    self.risk_scores["paste_sites"] += 5

        except Exception as e:
            self.logger.error(f"Error analyzing paste content: {str(e)}", exc_info=True)

    def _analyze_virustotal_data(self, vt_results: Dict, results: Dict):
        """Analyze VirusTotal results"""
        try:
            for item_type, data in vt_results.items():
                if "malicious" in data:
                    if data["malicious"] > 0:
                        activity = {
                            "type": "virustotal_detection",
                            "item_type": item_type,
                            "detections": data["malicious"],
                            "risk_level": "high" if data["malicious"] > 10 else "medium",
                            "timestamp": datetime.now().isoformat()
                        }
                        results["detected_activities"].append(activity)
                        results["indicators"]["high_risk"].append(activity)
                        self.risk_scores["virustotal"] += data["malicious"]

        except Exception as e:
            self.logger.error(f"Error analyzing VirusTotal data: {str(e)}", exc_info=True)

    def _analyze_shodan_data(self, shodan_results: Dict, results: Dict):
        """Analyze Shodan results"""
        try:
            for ip, data in shodan_results.items():
                if "vulns" in data:
                    activity = {
                        "type": "shodan_vulnerabilities",
                        "ip": ip,
                        "vulnerability_count": len(data["vulns"]),
                        "risk_level": "high" if len(data["vulns"]) > 5 else "medium",
                        "timestamp": datetime.now().isoformat()
                    }
                    results["detected_activities"].append(activity)
                    results["indicators"]["high_risk"].append(activity)
                    self.risk_scores["shodan"] += len(data["vulns"])

        except Exception as e:
            self.logger.error(f"Error analyzing Shodan data: {str(e)}", exc_info=True)

    def _apply_regex_patterns(self, text: str, source: str, results: Dict):
        """Apply regex patterns to text"""
        try:
            for pattern_name, pattern in self.patterns["regex_patterns"].items():
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    activity = {
                        "type": f"{source}_pattern_match",
                        "pattern_type": pattern_name,
                        "matched_text": match.group(),
                        "context": self._get_context(text, match.group()),
                        "risk_level": "medium",
                        "timestamp": datetime.now().isoformat()
                    }
                    results["detected_activities"].append(activity)
                    results["indicators"]["medium_risk"].append(activity)
                    self.risk_scores[source] += 5

        except Exception as e:
            self.logger.error(f"Error applying regex patterns: {str(e)}", exc_info=True)

    def _get_context(self, text: str, match: str, context_size: int = 100) -> str:
        """Get context around a matched string"""
        try:
            start = max(0, text.find(match) - context_size)
            end = min(len(text), text.find(match) + len(match) + context_size)
            return text[start:end].strip()
        except Exception:
            return ""

    def _calculate_overall_risk(self) -> int:
        """Calculate overall risk score"""
        total_score = sum(self.risk_scores.values())
        return min(100, total_score)  # Cap at 100

    def _generate_activity_timeline(self) -> List[Dict]:
        """Generate timeline of detected activities"""
        timeline = []

        for activity in self.detected_activities:
            timeline.append({
                "timestamp": activity.get("timestamp", datetime.now().isoformat()),
                "type": activity.get("type"),
                "risk_level": activity.get("risk_level"),
                "details": activity
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline