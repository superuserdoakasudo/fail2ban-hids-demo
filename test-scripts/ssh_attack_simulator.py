#!/usr/bin/env python3
"""
SSH Attack Simulator

This script simulates multiple SSH login attempts to test Fail2ban's detection capabilities.
It uses the Paramiko library to make SSH connection attempts with configurable parameters.

Usage:
    python ssh_attack_simulator.py --host 127.0.0.1 --port 22 --attempts 5 --delay 1 --username admin

Author: Student ID: 22332371
"""

import argparse
import logging
import time
import random
import sys
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("The paramiko library is required. Install it using: pip install paramiko")
    sys.exit(1)

# Configure logging
log_dir = Path(__file__).parent.parent / "logs"
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "ssh_attack_simulator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SSH-Attack-Simulator")

# List of common usernames for random selection if none provided
COMMON_USERNAMES = ["admin", "root", "user", "test", "guest", "administrator", "ubuntu"]

# List of common passwords for random selection
COMMON_PASSWORDS = ["password", "123456", "admin", "root", "qwerty", "letmein", "welcome", "password123"]


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Simulate SSH login attempts to test Fail2ban.')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Target host IP address')
    parser.add_argument('--port', type=int, default=22, help='SSH port number')
    parser.add_argument('--attempts', type=int, default=5, help='Number of login attempts')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between attempts in seconds')
    parser.add_argument('--username', type=str, help='Username to attempt (default: random selection)')
    parser.add_argument('--password', type=str, help='Password to attempt (default: random selection)')
    parser.add_argument('--random-creds', action='store_true', help='Use random credentials for each attempt')
    
    return parser.parse_args()


def simulate_ssh_attempt(host, port, username, password):
    """
    Attempt an SSH connection with the given credentials.
    
    Args:
        host (str): Target host IP address
        port (int): SSH port
        username (str): Username to attempt
        password (str): Password to attempt
        
    Returns:
        bool: True if successful, False otherwise
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        logger.info(f"Attempting SSH login to {host}:{port} with username '{username}'")
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False
        )
        logger.warning(f"SSH login successful with {username}:{password}! This is unexpected in a testing scenario.")
        return True
    except paramiko.AuthenticationException:
        logger.info(f"Authentication failed for {username}:{password}")
        return False
    except paramiko.SSHException as e:
        logger.error(f"SSH error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Connection error: {str(e)}")
        return False
    finally:
        client.close()


def main():
    """Main execution function."""
    args = parse_arguments()
    
    logger.info("=" * 50)
    logger.info(f"Starting SSH attack simulation against {args.host}:{args.port}")
    logger.info(f"Will perform {args.attempts} attempts with {args.delay}s delay between attempts")
    logger.info("=" * 50)
    
    successful_attempts = 0
    
    try:
        for i in range(args.attempts):
            # Determine credentials for this attempt
            if args.random_creds:
                username = args.username or random.choice(COMMON_USERNAMES)
                password = args.password or random.choice(COMMON_PASSWORDS)
            else:
                username = args.username or random.choice(COMMON_USERNAMES)
                password = args.password or random.choice(COMMON_PASSWORDS)
            
            logger.info(f"Attempt {i+1}/{args.attempts}")
            
            if simulate_ssh_attempt(args.host, args.port, username, password):
                successful_attempts += 1
            
            # Only delay if not the last attempt
            if i < args.attempts - 1:
                logger.debug(f"Waiting {args.delay} seconds before next attempt")
                time.sleep(args.delay)
    
    except KeyboardInterrupt:
        logger.info("Attack simulation interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    finally:
        logger.info("=" * 50)
        logger.info(f"SSH attack simulation completed: {successful_attempts}/{args.attempts} successful logins")
        logger.info("=" * 50)


if __name__ == "__main__":
    main()

