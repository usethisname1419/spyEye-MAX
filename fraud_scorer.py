# fraud_scorer.py
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json
from collections import defaultdict
import math
import aiohttp
import asyncio
import hashlib
import re
from urllib.parse import quote


class FraudScorer:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.api_keys = config.get("api_keys", {})
        self.session = None
        self.risk_factors = defaultdict(float)
        self.evidence = defaultdict(list)

        # Load configurations
        self.scoring_rules = self._load_scoring_rules()
        self.fraud_patterns = self._load_fraud_patterns()

        # Initialize score trackers
        self.phone_scores = defaultdict(list)
        self.email_scores = defaultdict(list)
        self.domain_scores = defaultdict(list)

        # API rate limiting
        self.rate_limits = {
            "emailrep": {"calls": 0, "reset_time": None},
            "numverify": {"calls": 0, "reset_time": None},
            "hibp": {"calls": 0, "reset_time": None}
        }

    def _load_scoring_rules(self) -> Dict:
        """Load fraud scoring rules from configuration"""
        try:
            with open('config/fraud_scoring_rules.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load fraud scoring rules: {str(e)}", exc_info=True)
            return {
                "weights": {
                    "phone_verification": 0.2,
                    "email_verification": 0.2,
                    "domain_analysis": 0.15,
                    "dark_web_presence": 0.15,
                    "social_media": 0.15,
                    "behavioral_patterns": 0.15
                },
                "thresholds": {
                    "high_risk": 75,
                    "medium_risk": 50,
                    "low_risk": 25
                },
                "risk_levels": {
                    "critical": {"min": 80, "max": 100},
                    "high": {"min": 60, "max": 79},
                    "medium": {"min": 40, "max": 59},
                    "low": {"min": 20, "max": 39},
                    "minimal": {"min": 0, "max": 19}
                }
            }

    def _load_fraud_patterns(self) -> Dict:
        """Load fraud detection patterns"""
        try:
            with open('config/fraud_patterns.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load fraud patterns: {str(e)}", exc_info=True)
            return {
                "email_patterns": {
                    "disposable_domains": [],
                    "suspicious_patterns": []
                },
                "phone_patterns": {
                    "high_risk_prefixes": [],
                    "voip_indicators": []
                },
                "behavioral_patterns": {
                    "suspicious_activities": [],
                    "risk_indicators": []
                }
            }

    async def initialize(self):
        """Initialize fraud scorer and API connections"""
        try:
            # Set up aiohttp session with timeout
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'User-Agent': 'SpyEye-Investigation-Tool/1.0',
                    'Accept': 'application/json'
                }
            )

            # Verify API keys
            missing_keys = self._verify_required_api_keys()
            if missing_keys:
                self.logger.warning(f"Missing API keys: {', '.join(missing_keys)}")

            self.logger.info("Fraud Scorer initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize Fraud Scorer: {str(e)}", exc_info=True)
            raise

    def _verify_required_api_keys(self) -> List[str]:
        """Verify all required API keys are present"""
        required_keys = {
            "numverify",
            "twilio_sid",
            "twilio_token",
            "phonevalidator",
            "emailrep",
            "hunter",
            "hibp"
        }

        missing_keys = []
        for key in required_keys:
            if not self.api_keys.get(key):
                missing_keys.append(key)

        return missing_keys

    async def calculate_comprehensive_score(self, target_info: Dict) -> Dict:
        """Calculate comprehensive fraud score for all target information"""
        results = {
            "overall_score": 0,
            "risk_level": "",
            "component_scores": {},
            "verification_results": {
                "phones": {},
                "emails": {},
                "domains": {}
            },
            "risk_factors": [],
            "evidence": [],
            "recommendations": [],
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0",
                "apis_used": []
            }
        }

        try:
            # Phone number verification
            for phone in target_info.get("phone_numbers", []):
                results["verification_results"]["phones"][phone] = \
                    await self._verify_phone_number(phone)

            # Email verification
            for email in target_info.get("emails", []):
                results["verification_results"]["emails"][email] = \
                    await self._verify_email(email)

            # Domain analysis
            for domain in target_info.get("domains", []):
                results["verification_results"]["domains"][domain] = \
                    await self._analyze_domain(domain)

            # Calculate component scores
            results["component_scores"] = await self._calculate_component_scores(
                results["verification_results"]
            )

            # Calculate overall score
            results["overall_score"] = self._calculate_weighted_score(
                results["component_scores"]
            )

            # Determine risk level
            results["risk_level"] = self._determine_risk_level(results["overall_score"])

            # Compile risk factors and evidence
            results["risk_factors"] = self._compile_risk_factors()
            results["evidence"] = self._compile_evidence()

            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(results)

            # Update metadata
            results["metadata"]["apis_used"] = self._get_apis_used()

            return results

        except Exception as e:
            self.logger.error(f"Error calculating comprehensive score: {str(e)}", exc_info=True)
            raise

    async def _verify_phone_number(self, phone: str) -> Dict:
        """Comprehensive phone number verification using multiple APIs"""
        results = {
            "score": 0,
            "flags": [],
            "api_results": {},
            "verification_status": "unknown",
            "risk_indicators": []
        }

        try:
            # NumVerify Check
            numverify_result = await self._check_numverify(phone)
            if numverify_result:
                results["api_results"]["numverify"] = numverify_result
                await self._process_numverify_results(numverify_result, results)

            # Twilio Lookup Check
            twilio_result = await self._check_twilio_lookup(phone)
            if twilio_result:
                results["api_results"]["twilio"] = twilio_result
                await self._process_twilio_results(twilio_result, results)

            # Phone Validator Check
            validator_result = await self._check_phone_validator(phone)
            if validator_result:
                results["api_results"]["phonevalidator"] = validator_result
                await self._process_phone_validator_results(validator_result, results)

            # Calculate final phone score
            results["score"] = self._calculate_phone_score(results)

            return results

        except Exception as e:
            self.logger.error(f"Error verifying phone number {phone}: {str(e)}", exc_info=True)
            results["error"] = str(e)
            return results

    async def _verify_email(self, email: str) -> Dict:
        """Comprehensive email verification using multiple APIs"""
        results = {
            "score": 0,
            "flags": [],
            "api_results": {},
            "verification_status": "unknown",
            "risk_indicators": []
        }

        try:
            # EmailRep Check
            emailrep_result = await self._check_emailrep(email)
            if emailrep_result:
                results["api_results"]["emailrep"] = emailrep_result
                await self._process_emailrep_results(emailrep_result, results)

            # Hunter.io Check
            hunter_result = await self._check_hunter(email)
            if hunter_result:
                results["api_results"]["hunter"] = hunter_result
                await self._process_hunter_results(hunter_result, results)

            # HaveIBeenPwned Check
            hibp_result = await self._check_hibp(email)
            if hibp_result:
                results["api_results"]["hibp"] = hibp_result
                await self._process_hibp_results(hibp_result, results)

            # Calculate final email score
            results["score"] = self._calculate_email_score(results)

            return results

        except Exception as e:
            self.logger.error(f"Error verifying email {email}: {str(e)}", exc_info=True)
            results["error"] = str(e)
            return results

    async def _analyze_domain(self, domain: str) -> Dict:
        """Analyze domain reputation and risk factors"""
        results = {
            "score": 0,
            "flags": [],
            "api_results": {},
            "verification_status": "unknown",
            "risk_indicators": []
        }

        try:
            # Domain age check
            domain_age = await self._check_domain_age(domain)
            if domain_age:
                results["domain_age"] = domain_age
                if domain_age < 30:  # Less than 30 days old
                    results["flags"].append("Recently registered domain")
                    results["score"] += 30

            # SSL certificate check
            ssl_info = await self._check_ssl_certificate(domain)
            if ssl_info:
                results["ssl_info"] = ssl_info
                if not ssl_info.get("valid"):
                    results["flags"].append("Invalid SSL certificate")
                    results["score"] += 20

            # Additional domain checks can be added here

            return results

        except Exception as e:
            self.logger.error(f"Error analyzing domain {domain}: {str(e)}", exc_info=True)
            results["error"] = str(e)
            return results

    async def _check_numverify(self, phone: str) -> Optional[Dict]:
        """Check phone number using NumVerify API"""
        try:
            if not self.api_keys.get("numverify"):
                return None

            url = "http://apilayer.net/api/validate"
            params = {
                "access_key": self.api_keys["numverify"],
                "number": phone,
                "format": 1
            }

            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "valid": data.get("valid", False),
                        "country": data.get("country_name"),
                        "carrier": data.get("carrier"),
                        "line_type": data.get("line_type"),
                        "raw_response": data
                    }
                return None

        except Exception as e:
            self.logger.error(f"NumVerify API error: {str(e)}", exc_info=True)
            return None

    async def _check_twilio_lookup(self, phone: str) -> Optional[Dict]:
        """Check phone number using Twilio Lookup API"""
        try:
            if not (self.api_keys.get("twilio_sid") and self.api_keys.get("twilio_token")):
                return None

            url = f"https://lookups.twilio.com/v1/PhoneNumbers/{phone}"
            auth = aiohttp.BasicAuth(
                self.api_keys["twilio_sid"],
                self.api_keys["twilio_token"]
            )

            async with self.session.get(url, auth=auth) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "valid": True,
                        "carrier": data.get("carrier", {}),
                        "country_code": data.get("country_code"),
                        "raw_response": data
                    }
                return None

        except Exception as e:
            self.logger.error(f"Twilio Lookup API error: {str(e)}", exc_info=True)
            return None

    async def _check_emailrep(self, email: str) -> Optional[Dict]:
        """Check email using EmailRep.io API"""
        try:
            if not self.api_keys.get("emailrep"):
                return None

            url = f"https://emailrep.io/{quote(email)}"
            headers = {"Key": self.api_keys["emailrep"]}

            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "reputation": data.get("reputation", "none"),
                        "suspicious": data.get("suspicious", False),
                        "references": data.get("references", 0),
                        "details": {
                            "blacklisted": data.get("details", {}).get("blacklisted", False),
                            "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                            "credential_leaked": data.get("details", {}).get("credential_leaked", False),
                            "data_breach": data.get("details", {}).get("data_breach", False)
                        },
                        "raw_response": data
                    }
                return None

        except Exception as e:
            self.logger.error(f"EmailRep API error: {str(e)}", exc_info=True)
            return None

    def _calculate_phone_score(self, results: Dict) -> int:
        """Calculate final phone number risk score"""
        score = 0

        # Base score from API results
        if results.get("api_results"):
            # NumVerify results
            numverify = results["api_results"].get("numverify", {})
            if not numverify.get("valid", True):
                score += 30
            if numverify.get("line_type") == "voip":
                score += 20

            # Twilio results
            twilio = results["api_results"].get("twilio", {})
            if not twilio.get("valid", True):
                score += 30
            if twilio.get("carrier", {}).get("type") == "voip":
                score += 20

            # Phone Validator results
            validator = results["api_results"].get("phonevalidator", {})
            if validator.get("fraud_score", 0) > 70:
                score += 40

        # Additional scoring based on flags
        score += len(results.get("flags", [])) * 10

        return min(100, score)  # Cap at 100

    def _calculate_email_score(self, results: Dict) -> int:
        """Calculate final email risk score"""
        score = 0

        # Base score from API results
        if results.get("api_results"):
            # EmailRep results
            emailrep = results["api_results"].get("emailrep", {})
            if emailrep.get("suspicious", False):
                score += 30
            if emailrep.get("details", {}).get("malicious_activity"):
                score += 40
            if emailrep.get("details", {}).get("credential_leaked"):
                score += 20

            # Hunter results
            hunter = results["api_results"].get("hunter", {})
            if not hunter.get("valid", True):
                score += 20
            if hunter.get("disposable", False):
                score += 35

            # HIBP results
            hibp = results["api_results"].get("hibp", [])
            breach_count = len(hibp)
            if breach_count > 0:
                score += min(breach_count * 5, 30)

        # Additional scoring based on flags
        score += len(results.get("flags", [])) * 10

        return min(100, score)  # Cap at 100

    async def _calculate_component_scores(self, verification_results: Dict) -> Dict:
        """Calculate scores for each component"""
        scores = {
            "phone_verification": 0,
            "email_verification": 0,
            "domain_analysis": 0
        }

        # Calculate phone scores
        phone_scores = [result["score"] for result in verification_results["phones"].values()]
        if phone_scores:
            scores["phone_verification"] = sum(phone_scores) / len(phone_scores)

        # Calculate email scores
        email_scores = [result["score"] for result in verification_results["emails"].values()]
        if email_scores:
            scores["email_verification"] = sum(email_scores) / len(email_scores)

        # Calculate domain scores
        domain_scores = [result["score"] for result in verification_results["domains"].values()]
        if domain_scores:
            scores["domain_analysis"] = sum(domain_scores) / len(domain_scores)

        return scores

    def _calculate_weighted_score(self, component_scores: Dict) -> float:
        """Calculate weighted overall score"""
        weights = self.scoring_rules["weights"]
        weighted_sum = 0
        weight_sum = 0

        for component, score in component_scores.items():
            if score > 0:  # Only consider components with actual scores
                weight = weights.get(component, 0)
                weighted_sum += score * weight
                weight_sum += weight

        if weight_sum == 0:
            return 0

        return round(weighted_sum / weight_sum, 2)

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
        for level, range_dict in self.scoring_rules["risk_levels"].items():
            if range_dict["min"] <= score <= range_dict["max"]:
                return level.upper()
        return "UNKNOWN"

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []

        # Risk level based recommendations
        if results["risk_level"] == "CRITICAL":
            recommendations.extend([
                "Immediate investigation required",
                "Consider blocking all associated accounts",
                "Report to relevant authorities",
                "Preserve all evidence for potential legal action"
            ])
        elif results["risk_level"] == "HIGH":
            recommendations.extend([
                "Detailed investigation recommended",
                "Implement enhanced monitoring",
                "Review all associated accounts",
                "Consider temporary access restrictions"
            ])
        elif results["risk_level"] == "MEDIUM":
            recommendations.extend([
                "Increase monitoring frequency",
                "Verify user identity through additional channels",
                "Review security controls"
            ])

        # Component-specific recommendations
        for component, score in results["component_scores"].items():
            if score > 75:
                recommendations.append(f"Investigate high risk {component}")
            elif score > 50:
                recommendations.append(f"Review {component} findings")

        return recommendations

    async def close(self):
        """Clean up resources"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
            self.logger.info("Fraud Scorer closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing Fraud Scorer: {str(e)}", exc_info=True)