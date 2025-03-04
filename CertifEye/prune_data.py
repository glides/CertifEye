#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Data Pruning Script
Author: glides
Version: 0.9.3

This script prunes a large CA logs dataset to create a manageable subset for model training.
"""

import sys
import logging
import argparse
import yaml
import pandas as pd
from colorama import init, Fore, Style
from tqdm import tqdm
from certifeye_utils import get_logger, load_config

# load config
config = load_config()

# Initialize colorama
init(autoreset=True)

def get_parser():
    parser = argparse.ArgumentParser(description='CertifEye - Data Pruning Script')
    parser.add_argument('-s', '--sample-size', type=int, default=config.get('pruning', {}).get('default_sample_size', 3000),help='Sample size of normal requests')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (e.g., -v, -vv)')
    return parser

def main(args=None):
    # === Configure Logging ===
    logger = get_logger('CertifEye-PruneData')

    # === Parse Command-Line Arguments ===
    parser = get_parser()
    if args is None:
        args = sys.argv[1:]
    try:
        args = parser.parse_args(args)
    except SystemExit:
        # Help message was displayed; return to console
        return

    # Adjust logging levels based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
        for handler in logger.handlers:
            handler.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
        for handler in logger.handlers:
            handler.setLevel(logging.WARNING)

    try:
        # Only print banner if this script is run directly
        # print_banner()  # Commented out to display banner only once in the console app

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
        logger.info(f"Loading full CA logs from: {ca_logs_full_path}")
        df_full = pd.read_csv(ca_logs_full_path)
        df_full['RequestID'] = df_full['RequestID'].astype(int)

        logger.info(f"{Fore.WHITE}Loaded CA logs with {len(df_full)} records.{Style.RESET_ALL}")

        if df_full.empty:
            logger.error(f"{Fore.RED}CA logs DataFrame is empty. No data to prune.{Style.RESET_ALL}")
            return

        # === Split the Data ===

        # Identify known abuse instances
        df_abuse = df_full[df_full['RequestID'].isin(known_abuse_request_ids_set)]

        # Identify known good instances
        df_known_good = df_full[df_full['RequestID'].isin(known_good_request_ids_set)]

        # Exclude known abuse and known good instances to get normal requests
        df_normal = df_full[
            ~df_full['RequestID'].isin(known_abuse_request_ids_set.union(known_good_request_ids_set))
        ]

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
        df_combined = pd.concat([df_normal_sampled, df_abuse, df_known_good], ignore_index=True)

        # Verify the counts
        total_records = len(df_combined)
        normal_requests = len(df_normal_sampled)
        abuse_requests = len(df_abuse)
        known_good_requests = len(df_known_good)

        # Print the counts
        logger.info(f"{Fore.YELLOW}Total records in combined dataset: {Fore.LIGHTBLACK_EX}{total_records}{Style.RESET_ALL}")
        logger.info(f"{Fore.WHITE}Normal requests: {Fore.LIGHTBLACK_EX}{normal_requests}{Style.RESET_ALL}")
        logger.info(f"{Fore.WHITE}Known abuse requests: {Fore.LIGHTBLACK_EX}{abuse_requests}{Style.RESET_ALL}")
        logger.info(f"{Fore.WHITE}Known good requests: {Fore.LIGHTBLACK_EX}{known_good_requests}{Style.RESET_ALL}")

        # Save the combined dataset to the pruned CA logs path
        df_combined.to_csv(ca_logs_pruned_path, index=False)
        logger.info(f"{Fore.GREEN}Combined dataset saved to: {Fore.LIGHTBLACK_EX}{ca_logs_pruned_path}{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperation cancelled by user. Returning to console.{Style.RESET_ALL}")
        return
    except FileNotFoundError as fnf_error:
        logger.error(f"{Fore.RED}File not found: {fnf_error}{Style.RESET_ALL}", exc_info=args.verbose >= 1)
    except Exception as e:
        logger.error(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}", exc_info=args.verbose >= 1)

if __name__ == '__main__':
    main()
