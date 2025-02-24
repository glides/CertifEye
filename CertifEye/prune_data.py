# prune_data.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Data Pruning Script
Author: glides
Version: 1.0

This script prunes a large CA logs dataset to create a manageable subset for model training.
"""

import sys
import logging
import argparse
import yaml
import pandas as pd
from colorama import init, Fore, Style
from certifeye_utils import print_banner

# Initialize colorama
init(autoreset=True)

# === Configure Logging ===

# Create logger
logger = logging.getLogger('CertifEye-PruneData')
logger.setLevel(logging.DEBUG)

# Create handlers
file_handler = logging.FileHandler('prune_data.log')
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Create formatters and add them to handlers
file_formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
console_formatter = logging.Formatter('%(message)s')

file_handler.setFormatter(file_formatter)
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# === Parse Command-Line Arguments ===

parser = argparse.ArgumentParser(description='CertifEye - Data Pruning Script')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('-s', '--sample-size', type=int, default=3000, help='Sample size of normal requests')
args = parser.parse_args()

if args.verbose:
    console_handler.setLevel(logging.DEBUG)

# === Main Execution ===

if __name__ == '__main__':
    try:
        print_banner()

        # === Load Configuration ===

        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)

        # Paths from config
        ca_logs_full_path = config['paths']['ca_logs_full_path']
        ca_logs_pruned_path = config['paths']['ca_logs_pruned_path']

        # Known abuse and known good Request IDs from config
        known_abuse_request_ids = config.get('known_abuse_request_ids', [])
        known_good_request_ids = config.get('known_good_request_ids', [])

        # Convert IDs to sets for faster lookup
        known_abuse_request_ids_set = set(known_abuse_request_ids)
        known_good_request_ids_set = set(known_good_request_ids)

        # === Load the Full CA Logs ===

        df_full = pd.read_csv(ca_logs_full_path)
        df_full['RequestID'] = df_full['RequestID'].astype(int)

        logger.info(f"{Fore.CYAN}Loaded full CA logs with {len(df_full)} records.{Style.RESET_ALL}")

        # === Split the Data ===

        df_abuse = df_full[df_full['RequestID'].isin(known_abuse_request_ids_set)]
        df_known_good = df_full[df_full['RequestID'].isin(known_good_request_ids_set)]
        df_normal = df_full[~df_full['RequestID'].isin(known_abuse_request_ids_set.union(known_good_request_ids_set))]

        # Verify that known abuse instances are present
        if df_abuse.empty:
            logger.warning(f"{Fore.YELLOW}No known abuse instances found in the CA logs.{Style.RESET_ALL}")
        else:
            logger.info(f"{Fore.CYAN}Found {len(df_abuse)} known abuse instances.{Style.RESET_ALL}")

        # Sample a subset of normal requests
        sample_size = args.sample_size  # Default is 3000 if not specified
        if len(df_normal) < sample_size:
            sample_size = len(df_normal)
            logger.warning(f"{Fore.YELLOW}Requested sample size exceeds available normal requests. Using {sample_size} instead.{Style.RESET_ALL}")

        df_normal_sampled = df_normal.sample(n=sample_size, random_state=42)
        logger.info(f"{Fore.CYAN}Sampled {len(df_normal_sampled)} normal requests.{Style.RESET_ALL}")

        # Combine the sampled normal requests with known abuse and known good instances
        df_combined = pd.concat([df_normal_sampled, df_abuse, df_known_good])

        # Save the combined dataset to the pruned CA logs path
        df_combined.to_csv(ca_logs_pruned_path, index=False)
        logger.info(f"{Fore.GREEN}Combined dataset saved to {ca_logs_pruned_path}{Style.RESET_ALL}")

        # Optional: Verify the counts
        total_records = len(df_combined)
        normal_requests = len(df_normal_sampled)
        abuse_requests = len(df_abuse)
        known_good_requests = len(df_known_good)

        logger.info(f"{Fore.CYAN}Total records in combined dataset: {total_records}{Style.RESET_ALL}")
        logger.info(f"Number of normal requests: {normal_requests}")
        logger.info(f"Number of known abuse requests: {abuse_requests}")
        logger.info(f"Number of known good requests: {known_good_requests}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperation cancelled by user. Exiting gracefully.{Style.RESET_ALL}")
        sys.exit(0)
    except FileNotFoundError as fnf_error:
        logger.error(f"{Fore.RED}File not found: {fnf_error}{Style.RESET_ALL}", exc_info=True)
    except Exception as e:
        logger.error(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}", exc_info=True)
