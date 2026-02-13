#!/usr/bin/env python3
"""
ServerControl Pro - Professional Server Management Application
==============================================================
Entry point for the desktop application.

This module initializes the application, loads configuration,
sets up logging, and launches the main UI.
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Create required directories
DIRS = ['logs', 'data', 'config', 'assets']
for dir_name in DIRS:
    (PROJECT_ROOT / dir_name).mkdir(exist_ok=True)

# Configure logging
LOG_FILE = PROJECT_ROOT / 'logs' / f'servercontrol_{datetime.now():%Y%m%d}.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('ServerControlPro')


def check_dependencies() -> bool:
    """
    Verify all required dependencies are installed.

    Returns:
        bool: True if all dependencies available
    """
    missing = []

    try:
        import paramiko
    except ImportError:
        missing.append('paramiko')

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        missing.append('cryptography')

    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        missing.append('tkinter')

    if missing:
        logger.error(f"Missing dependencies: {', '.join(missing)}")
        print(f"\nMissing dependencies: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt\n")
        return False

    return True


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='ServerControl Pro - Server Management Application',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Start the application
  python main.py --config custom/   Use custom config directory
  python main.py --debug            Enable debug logging
        """
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config',
        help='Path to configuration directory'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    parser.add_argument(
        '--reset-credentials',
        action='store_true',
        help='Reset stored credentials'
    )

    return parser.parse_args()


def main():
    """Main application entry point."""
    print("\n" + "=" * 60)
    print("  ⚡ ServerControl Pro")
    print("  Professional Server Management")
    print("=" * 60)

    # Parse arguments
    args = parse_arguments()

    # Set debug level if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Import application components
    from core.security import SecurityManager
    from ui.app import ServerControlApp

    # Initialize security manager
    security = SecurityManager(data_dir=PROJECT_ROOT / 'data')

    # Reset credentials if requested
    if args.reset_credentials:
        logger.info("Resetting stored credentials...")
        security.reset_credentials()
        print("Credentials reset successfully.")

    # Configuration paths
    config_dir = Path(args.config)
    if not config_dir.is_absolute():
        config_dir = PROJECT_ROOT / config_dir

    servers_config = config_dir / 'servers.json'
    roles_config = config_dir / 'roles.json'

    # Validate configuration files exist
    if not servers_config.exists():
        logger.error(f"Server configuration not found: {servers_config}")
        print(f"\nError: Configuration file not found: {servers_config}")
        print("Create the configuration file or specify --config path\n")
        sys.exit(1)

    if not roles_config.exists():
        logger.warning(f"Roles configuration not found: {roles_config}")
        logger.warning("Using default role configuration")

    logger.info(f"Configuration directory: {config_dir}")
    logger.info(f"Starting ServerControl Pro...")

    # Launch application
    try:
        app = ServerControlApp(
            servers_config=servers_config,
            roles_config=roles_config,
            security_manager=security,
            icon_path=PROJECT_ROOT / 'assets' / 'icon.png'
        )
        app.run()

    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.exception(f"Application error: {e}")
        raise
    finally:
        logger.info("ServerControl Pro shutdown complete")


if __name__ == '__main__':
    main()
