import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger():
    """Configure logging with both file and console handlers"""
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )

    # Set up file handler
    log_file = log_dir / f"spyeye_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    # Set up console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def log_error_with_traceback(logger, error_msg, exc_info=None):
    """Log error with full traceback if exception info is provided"""
    if exc_info:
        logger.error(f"{error_msg}", exc_info=exc_info)
    else:
        logger.error(error_msg)