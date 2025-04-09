#!/usr/bin/env python3
"""
Fail2ban Monitoring Tool

This script monitors Fail2ban logs in real-time, analyzes ban events,
and generates statistics about attack patterns and IPs.

Author: Student ID: 22332371
"""

import argparse
import json
import csv
import re
import time
import logging
import os
import sys
import signal
import datetime
from collections import Counter, defaultdict
from pathlib import Path
import threading
import queue
from typing import Dict, List, Tuple, Optional, Any

# Configure logging
log_dir = Path(__file__).parent.parent / "logs"
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "fail2ban_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Fail2ban-Monitor")

# Define regex patterns for Fail2ban log parsing
BAN_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) fail2ban\.actions\s+\[\d+\]: (INFO|NOTICE)\s+\[([^\]]+)\] Ban (\S+)')
UNBAN_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) fail2ban\.actions\s+\[\d+\]: (INFO|NOTICE)\s+\[([^\]]+)\] Unban (\S+)')
FIND_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) fail2ban\.filter\s+\[\d+\]: (INFO|NOTICE)\s+\[([^\]]+)\] Found (\S+)')


class Fail2banStats:
    """Class to track and analyze Fail2ban statistics."""
    
    def __init__(self):
        self.ban_count = 0
        self.unban_count = 0
        self.find_count = 0
        self.banned_ips = Counter()
        self.jail_stats = defaultdict(lambda: {'bans': 0, 'unbans': 0, 'finds': 0})
        self.hourly_stats = defaultdict(int)
        self.ip_jail_map = defaultdict(set)
        self.ban_times = {}  # IP -> ban time
        self.start_time = datetime.datetime.now()
        self.lock = threading.Lock()
    
    def record_ban(self, timestamp: str, jail: str, ip: str) -> None:
        """Record a ban event."""
        with self.lock:
            self.ban_count += 1
            self.banned_ips[ip] += 1
            self.jail_stats[jail]['bans'] += 1
            self.ip_jail_map[ip].add(jail)
            
            # Record ban time
            try:
                dt = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S,%f")
                hour = dt.strftime("%Y-%m-%d %H")
                self.hourly_stats[hour] += 1
                self.ban_times[ip] = dt
            except ValueError:
                logger.error(f"Failed to parse timestamp: {timestamp}")
    
    def record_unban(self, timestamp: str, jail: str, ip: str) -> None:
        """Record an unban event."""
        with self.lock:
            self.unban_count += 1
            self.jail_stats[jail]['unbans'] += 1
    
    def record_find(self, timestamp: str, jail: str, ip: str) -> None:
        """Record a find event (when Fail2ban finds an attack attempt)."""
        with self.lock:
            self.find_count += 1
            self.jail_stats[jail]['finds'] += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of current statistics."""
        with self.lock:
            runtime = datetime.datetime.now() - self.start_time
            top_ips = self.banned_ips.most_common(10)
            top_jails = sorted(
                [(jail, stats['bans']) for jail, stats in self.jail_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )
            
            # Calculate ban frequency (bans per hour)
            hours = max(runtime.total_seconds() / 3600, 0.01)  # Avoid division by zero
            ban_frequency = self.ban_count / hours
            
            # Calculate attack detection rate
            detection_rate = 0
            if self.find_count > 0:
                detection_rate = (self.ban_count / self.find_count) * 100
            
            return {
                'runtime': str(runtime).split('.')[0],  # Remove microseconds
                'total_bans': self.ban_count,
                'total_unbans': self.unban_count,
                'total_finds': self.find_count,
                'unique_ips': len(self.banned_ips),
                'top_banned_ips': top_ips,
                'top_jails': top_jails,
                'ban_frequency': f"{ban_frequency:.2f} bans/hour",
                'detection_rate': f"{detection_rate:.2f}%",
                'hourly_distribution': dict(sorted(self.hourly_stats.items())),
            }
    
    def export_to_json(self, filepath: str) -> None:
        """Export statistics to a JSON file."""
        with self.lock:
            data = {
                'summary': {
                    'runtime': str(datetime.datetime.now() - self.start_time).split('.')[0],
                    'total_bans': self.ban_count,
                    'total_unbans': self.unban_count,
                    'total_finds': self.find_count,
                    'unique_ips': len(self.banned_ips),
                },
                'banned_ips': {ip: count for ip, count in self.banned_ips.items()},
                'jail_stats': dict(self.jail_stats),
                'hourly_stats': dict(self.hourly_stats),
                'ip_jail_mapping': {ip: list(jails) for ip, jails in self.ip_jail_map.items()},
                'timestamp': datetime.datetime.now().isoformat(),
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Statistics exported to {filepath}")
    
    def export_to_csv(self, filepath: str) -> None:
        """Export banned IP data to a CSV file."""
        with self.lock:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Ban Count', 'Jails'])
                
                for ip, count in self.banned_ips.most_common():
                    writer.writerow([ip, count, ', '.join(self.ip_jail_map[ip])])
            
            logger.info(f"IP ban data exported to {filepath}")
    
    def print_ascii_chart(self) -> None:
        """Print an ASCII chart of hourly ban distribution."""
        with self.lock:
            if not self.hourly_stats:
                print("No hourly data available yet.")
                return
            
            print("\nHourly Ban Distribution:")
            print("========================")
            
            # Find the max value for scaling
            max_value = max(self.hourly_stats.values())
            scale_factor = 50 / max(max_value, 1)  # Scale to 50 chars width max
            
            # Sort by hour and print
            for hour, count in sorted(self.hourly_stats.items()):
                bar_length = int(count * scale_factor)
                bar = '█' * bar_length
                print(f"{hour}: {bar} ({count})")
            
            print("========================\n")


class LogMonitor:
    """Class to monitor Fail2ban log file in real-time."""
    
    def __init__(self, log_path: str, stats: Fail2banStats):
        self.log_path = log_path
        self.stats = stats
        self.running = False
        self.thread = None
        self.last_position = 0
    
    def start(self) -> None:
        """Start the log monitoring thread."""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_log)
        self.thread.daemon = True
        self.thread.start()
        logger.info(f"Started monitoring {self.log_path}")
    
    def stop(self) -> None:
        """Stop the log monitoring thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        logger.info("Stopped log monitoring")
    
    def _monitor_log(self) -> None:
        """Monitor the log file for new entries."""
        # Initialize log file if it exists
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, 'r') as f:
                    f.seek(0, os.SEEK_END)
                    self.last_position = f.tell()
        except Exception as e:
            logger.error(f"Error initializing log file: {str(e)}")
            return
        
        # Main monitoring loop
        while self.running:
            try:
                if not os.path.exists(self.log_path):
                    time.sleep(1)
                    continue
                
                with open(self.log_path, 'r') as f:
                    f.seek(self.last_position)
                    for line in f:
                        self._process_line(line.strip())
                    self.last_position = f.tell()
                
                time.sleep(0.1)  # Small delay to reduce CPU usage
            except Exception as e:
                logger.error(f"Error monitoring log: {str(e)}")
                time.sleep(5)  # Longer delay on error
    
    def _process_line(self, line: str) -> None:
        """Process a single log line."""
        # Check for ban events
        ban_match = BAN_PATTERN.search(line)
        if ban_match:
            timestamp, _, jail, ip = ban_match.groups()
            self.stats.record_ban(timestamp, jail, ip)
            logger.debug(f"Recorded ban: {jail} banned {ip}")
            return
        
        # Check for unban events
        unban_match = UNBAN_PATTERN.search(line)
        if unban_match:
            timestamp, _, jail, ip = unban_match.groups()
            self.stats.record_unban(timestamp, jail, ip)
            logger.debug(f"Recorded unban: {jail} unbanned {ip}")
            return
        
        # Check for find events
        find_match = FIND_PATTERN.search(line)
        if find_match:
            timestamp, _, jail, ip = find_match.groups()
            self.stats.record_find(timestamp, jail, ip)
            logger.debug(f"Recorded find: {jail} found {ip}")
            return


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Monitor Fail2ban logs and generate statistics.')
    parser.add_argument(
        '--log', 
        type=str, 
        default='/var/log/fail2ban.log',
        help='Path to the Fail2ban log file (default: /var/log/fail2ban.log)'
    )
    parser.add_argument(
        '--interval', 
        type=int, 
        default=60,
        help='Interval in seconds between status updates (default: 60)'
    )
    parser.add_argument(
        '--output-dir', 
        type=str, 
        default=str(Path(__file__).parent.parent / "results"),
        help='Directory for output files'
    )
    return parser.parse_args()


def setup_signal_handlers(monitor, stats, output_dir):
    """Set up signal handlers for graceful shutdown."""
    def signal_handler(sig, frame):
        print("\nShutdown requested. Saving final results...")
        monitor.stop()
        
        # Export final results
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        stats.export_to_json(os.path.join(output_dir, f"fail2ban_stats_{timestamp}.json"))
        stats.export_to_csv(os.path.join(output_dir, f"banned_ips_{timestamp}.csv"))
        stats.print_ascii_chart()
        
        print("Final statistics:")
        summary = stats.get_summary()
        print(json.dumps(summary, indent=2))
        
        print("\nMonitoring completed. Final results saved to output directory.")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main execution function."""
    args = parse_arguments()
    
    # Ensure output directory exists
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)
    
    logger.info("=" * 60)
    logger.info(f"Starting Fail2ban Monitor")
    logger.info(f"Monitoring log file: {args.log}")
    logger.info(f"Update interval: {args.interval} seconds")
    logger.info(f"Output directory: {output_dir}")
    logger.info("=" * 60)
    
    # Initialize statistics tracker and log monitor
    stats = Fail2banStats()
    monitor = LogMonitor(args.log, stats)
    
    # Set up signal handlers
    setup_signal_handlers(monitor, stats, output_dir)
    
    # Start monitoring
    monitor.start()
    
    try:
        # Main loop for periodic updates
        while True:
            time.sleep(args.interval)
            
            # Display current statistics
            summary = stats.get_summary()
            print("\n" + "=" * 60)
            print(f"Fail2ban Monitor Status Update ({summary['runtime']} elapsed)")
            print("=" * 60)
            print(f"Total Bans: {summary['total_bans']}")
            print(f"Total Unbans: {summary['total_unbans']}")
            print(f"Unique IPs Banned: {summary['unique_ips']}")
            print(f"Attack Detection Rate: {summary['detection_rate']}")
            print(f"Ban Frequency: {summary['ban_frequency']}")
            
            # Top banned IPs
            # Top banned IPs
            if summary['top_banned_ips']:
                print("\nTop Banned IPs:")
                for ip, count in summary['top_banned_ips']:
                    print(f"{ip}: {count} times")
            
            # Top jails
            if summary['top_jails']:
                print("\nMost Active Jails:")
                for jail, ban_count in summary['top_jails']:
                    print(f"{jail}: {ban_count} bans")
            
            # Export data periodically
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            stats.export_to_json(os.path.join(output_dir, f"fail2ban_stats_latest.json"))
            
            # Print a mini chart of hourly distribution if available
            if summary['hourly_distribution']:
                print("\nHourly Ban Activity (last 5 hours):")
                for hour, count in list(summary['hourly_distribution'].items())[-5:]:
                    print(f"{hour}: {count} bans")
            
    except KeyboardInterrupt:
        print("\nUser interrupted monitoring.")
    finally:
        # Ensure we stop the monitor
        monitor.stop()
        
        # Save final results
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        stats.export_to_json(os.path.join(output_dir, f"fail2ban_stats_{timestamp}.json"))
        stats.export_to_csv(os.path.join(output_dir, f"banned_ips_{timestamp}.csv"))
        
        print("\nMonitoring stopped. Final results saved to output directory.")


if __name__ == "__main__":
    main()
