import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException
import os
import platform
import subprocess


class SeleniumManager:
    def __init__(self, use_tor=False, headless=True):
        self.logger = logging.getLogger(__name__)
        self.driver = None
        self.use_tor = use_tor
        self.headless = headless

    def setup_chrome_options(self):
        """Configure Chrome options with proper error handling"""
        try:
            chrome_options = Options()
            if self.headless:
                chrome_options.add_argument('--headless')

            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-extensions')

            if self.use_tor:
                chrome_options.add_argument('--proxy-server=socks5://127.0.0.1:9050')

            return chrome_options
        except Exception as e:
            self.logger.error(f"Failed to setup Chrome options: {str(e)}", exc_info=True)
            raise

    def verify_chrome_installation(self):
        """Verify Chrome browser is installed and accessible"""
        try:
            system = platform.system().lower()
            if system == 'linux':
                chrome_paths = [
                    '/usr/bin/google-chrome',
                    '/usr/bin/chrome',
                    '/usr/bin/chromium',
                    '/usr/bin/chromium-browser'
                ]
                for path in chrome_paths:
                    if os.path.exists(path):
                        return path

                # Try to install Chrome if not found
                self.logger.info("Chrome not found. Attempting to install...")
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 'google-chrome-stable'], check=True)

            elif system == 'windows':
                chrome_paths = [
                    r'C:\Program Files\Google\Chrome\Application\chrome.exe',
                    r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
                ]
                for path in chrome_paths:
                    if os.path.exists(path):
                        return path

            elif system == 'darwin':  # macOS
                if os.path.exists('/Applications/Google Chrome.app'):
                    return '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

            raise Exception("Chrome browser not found. Please install Google Chrome.")

        except Exception as e:
            self.logger.error(f"Failed to verify Chrome installation: {str(e)}", exc_info=True)
            raise

    def initialize_driver(self):
        """Initialize Chrome WebDriver with proper error handling"""
        try:
            self.verify_chrome_installation()
            chrome_options = self.setup_chrome_options()

            # Use webdriver_manager to handle driver installation
            service = Service(ChromeDriverManager().install())

            self.driver = webdriver.Chrome(
                service=service,
                options=chrome_options
            )

            self.logger.info("Chrome WebDriver initialized successfully")
            return self.driver

        except WebDriverException as e:
            self.logger.error(f"WebDriver initialization failed: {str(e)}", exc_info=True)
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during driver initialization: {str(e)}", exc_info=True)
            raise

    def quit(self):
        """Safely quit the WebDriver"""
        try:
            if self.driver:
                self.driver.quit()
                self.driver = None
                self.logger.info("WebDriver closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing WebDriver: {str(e)}", exc_info=True)