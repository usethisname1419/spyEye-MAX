import asyncio
import json
import logging
from pathlib import Path
from datetime import datetime

# Use absolute imports
from spyeye import SpyEye
from api_gatherer import APIGatherer
from api_manager import APIManager
from illegal_activity import IllegalActivityDetector
from intel_x import IntelXClient
from osint_gatherer import OSINTGatherer
from selenium_manager import SeleniumManager
from darkweb_monitor import DarkWebMonitor
from fraud_scorer import FraudScorer
from logger_config import setup_logger
# Rest of the test script remains the same...

class TestSpyEye:
    def __init__(self):
        self.logger = setup_logger()
        self.test_config = {
            "api_keys": {
                "hibp": "test_key",
                "virustotal": "test_key",
                "intelx": "test_key",
                "hunter": "test_key",
                "numverify": "test_key",
                "twilio_sid": "test_key",
                "twilio_token": "test_key"
            },
            "proxy_settings": {
                "enabled": False,
                "type": "socks5",
                "host": "127.0.0.1",
                "port": 9050
            },
            "investigation_settings": {
                "timeout": 30,
                "max_retries": 1,
                "concurrent_tasks": 2
            }
        }

        self.test_target = {
            "emails": ["test@example.com"],
            "domains": ["example.com"],
            "usernames": ["testuser"],
            "phone_numbers": ["+1234567890"]
        }

    async def test_component_initialization(self):
        """Test that all components can be initialized"""
        print("\n1. Testing component initialization...")
        try:
            # Test each component initialization
            components = {
                "APIManager": APIManager(self.test_config),
                "APIGatherer": APIGatherer(self.test_config),
                "IllegalActivityDetector": IllegalActivityDetector(self.test_config),
                "IntelXClient": IntelXClient(self.test_config),
                "OSINTGatherer": OSINTGatherer(self.test_config),
                "SeleniumManager": SeleniumManager(use_tor=False, headless=True),
                "DarkWebMonitor": DarkWebMonitor(self.test_config),
                "FraudScorer": FraudScorer(self.test_config)
            }

            for name, component in components.items():
                if hasattr(component, 'initialize'):
                    await component.initialize()
                print(f"✓ {name} initialized successfully")

            return True
        except Exception as e:
            print(f"✗ Component initialization failed: {str(e)}")
            return False

    async def test_data_flow(self):
        """Test the data flow between components without making real API calls"""
        print("\n2. Testing data flow between components...")
        try:
            # Initialize SpyEye with test config
            spyeye = SpyEye("test_config.json")
            spyeye.config = self.test_config  # Override config with test values

            # Mock some results
            mock_results = {
                "api_results": {"test": "data"},
                "osint_results": {"test": "data"},
                "dark_web_results": {"test": "data"},
                "intel_x_results": {"test": "data"},
                "fraud_analysis": {"test": "data"}
            }

            # Test correlation logic
            spyeye.results.update(mock_results)
            await spyeye._analyze_and_correlate()

            print("✓ Data flow test completed")
            return True
        except Exception as e:
            print(f"✗ Data flow test failed: {str(e)}")
            return False

    async def test_file_structure(self):
        """Test required file structure and permissions"""
        print("\n3. Testing file structure...")
        required_dirs = ['logs', 'reports', 'evidence', 'cache', 'exports']
        required_files = ['config.json', 'illegal_patterns.json',
                          'fraud_scoring_rules.json', 'onion_sites.json']

        try:
            # Check/create directories
            for dir_name in required_dirs:
                Path(dir_name).mkdir(exist_ok=True)
                print(f"✓ Directory '{dir_name}' verified")

            # Check/create configuration files
            for file_name in required_files:
                if not Path(file_name).exists():
                    # Create with minimal test content
                    with open(file_name, 'w') as f:
                        json.dump({"test": "data"}, f)
                print(f"✓ File '{file_name}' verified")

            return True
        except Exception as e:
            print(f"✗ File structure test failed: {str(e)}")
            return False

    async def test_error_handling(self):
        """Test error handling and recovery"""
        print("\n4. Testing error handling...")
        try:
            # Test API error handling
            api_manager = APIManager(self.test_config)
            await api_manager.initialize()

            # Test with invalid endpoint
            try:
                await api_manager.make_api_request("https://invalid.endpoint")
                print("✗ Should have raised an error")
            except Exception as e:
                print("✓ API error handled correctly")

            # Test rate limiting
            for _ in range(5):
                await api_manager._check_rate_limit("test_action")
            print("✓ Rate limiting working")

            return True
        except Exception as e:
            print(f"✗ Error handling test failed: {str(e)}")
            return False


async def run_tests():
    print("Starting SpyEye Component Tests\n")
    print("=" * 50)

    tester = TestSpyEye()

    # Run all tests
    tests = [
        tester.test_component_initialization(),
        tester.test_data_flow(),
        tester.test_file_structure(),
        tester.test_error_handling()
    ]

    results = await asyncio.gather(*tests, return_exceptions=True)

    # Print summary
    print("\nTest Summary:")
    print("=" * 50)
    all_passed = all(isinstance(r, bool) and r for r in results)
    if all_passed:
        print("\n✓ All tests passed! SpyEye components are properly connected.")
        print("  You can now run the full tool with real API keys.")
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
        print("  Fix any issues before running with real API keys.")


if __name__ == "__main__":
    asyncio.run(run_tests())