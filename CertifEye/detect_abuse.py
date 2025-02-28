#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - AD CS Abuse Detection Module
Author: glides
Version: 0.9.1

This script detects potential abuses of Active Directory Certificate Services.
"""

import argparse
import csv
import logging
import sys
import yaml
import joblib
import pickle
import pandas as pd
import numpy as np
import shap
from datetime import datetime
from tqdm import tqdm
from colorama import init, Fore, Style
from certifeye_utils import (
    #print_banner,
    detect_abuse,
    sanitize_request_data,
    TqdmLoggingHandler,
)

# Initialize colorama
init(autoreset=True)

# === Configure Logging ===
logger = logging.getLogger('CertifEye-DetectAbuse')
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    # File handler for logging to a file
    file_handler = logging.FileHandler('certifeye_detect_abuse.log')
    file_handler.setLevel(logging.INFO)

    # Console handler with tqdm support
    console_handler = TqdmLoggingHandler()
    console_handler.setLevel(logging.INFO)

    # Logging formatters
    file_formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
    console_formatter = logging.Formatter('%(message)s')

    file_handler.setFormatter(file_formatter)
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# === Parse Command-Line Arguments ===
def get_parser():
    parser = argparse.ArgumentParser(description='CertifEye - AD CS Abuse Detection Tool')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-r', '--redact', action='store_true', help='Redact sensitive data in logs/output')
    parser.add_argument('-f', '--show-features', action='store_true', help='Show feature contributions for all requests')
    return parser


def main(args=None):
    parser = get_parser()
    if args is None:
        args = sys.argv[1:]
    args = parser.parse_args(args)

    

    # === Main Execution ===
    try:
        #print_banner()

        # === Load Configuration ===
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)

        # Paths
        ca_logs_detection_path = config['paths']['ca_logs_detection_path']
        model_output_path = config['paths']['model_output_path']
        params_output_path = config['paths']['params_output_path']

        # Custom Classification Threshold
        classification_threshold = config.get('classification_threshold', 0.5)  # Default to 0.5 if not set

        # Load Trained Model and Parameters
        logger.info(
            f"{Fore.WHITE}Loading trained model from: {Fore.LIGHTBLACK_EX}%s{Style.RESET_ALL}",
            model_output_path
        )
        clf = joblib.load(model_output_path)

        logger.info(
            f"{Fore.WHITE}Loading parameters from: {Fore.LIGHTBLACK_EX}%s{Style.RESET_ALL}",
            params_output_path
        )
        with open(params_output_path, 'rb') as f:
            params = pickle.load(f)

        # Extract parameters
        feature_cols = params['feature_cols']
        validity_threshold = params['validity_threshold']
        training_mode = params.get('training_mode', 'supervised')
        disposition_categories = params.get('disposition_categories', [])
        pattern = params['pattern']
        vulnerable_templates = params['vulnerable_templates']
        templates_requiring_approval = params.get('templates_requiring_approval', [])
        authorized_client_auth_users = params.get('authorized_client_auth_users', [])
        authorized_client_auth_users = [user.lower() for user in authorized_client_auth_users]

        # Extract scaler and classifier from the pipeline
        scaler = clf.named_steps['scaler']
        classifier = clf.named_steps['classifier']

        # === Load SHAP Explainer ===
        explainer = shap.TreeExplainer(classifier)

        # === Load New Requests from CSV ===
        logger.info(
            f"{Fore.WHITE}Loading CA logs for detection from: {Fore.LIGHTBLACK_EX}%s{Style.RESET_ALL}",
            ca_logs_detection_path
        )
        try:
            new_requests_df = pd.read_csv(
                ca_logs_detection_path,
                quoting=csv.QUOTE_MINIMAL,
                escapechar='\\',
                engine='python',
                sep=','
            )
        except ValueError as ve:
            logger.warning(f"Error reading CSV with 'python' engine: {ve}")
            logger.info("Attempting to read the CSV without specifying the engine.")
            new_requests_df = pd.read_csv(
                ca_logs_detection_path,
                quoting=csv.QUOTE_MINIMAL,
                escapechar='\\',
                sep=','
            )

        # Handle multi-line fields in 'CertificateSANs'
        if 'CertificateSANs' in new_requests_df.columns:
            new_requests_df['CertificateSANs'] = new_requests_df['CertificateSANs'].astype(str).str.replace('\n', ' ').str.replace('\r', ' ')

        # Check if DataFrame is empty
        if new_requests_df.empty:
            logger.warning("No new requests to process.")
            return

        total_requests = len(new_requests_df)
        logger.info(f"{Fore.CYAN}Processing {total_requests} new certificate requests.{Style.RESET_ALL}")

        potential_abuses = 0  # Counter for detected abuses

        # Use progress bar if not showing features for all requests
        use_progress_bar = not args.show_features

        if use_progress_bar:
            bar_format = (
                f'{Fore.YELLOW}{{l_bar}}{Style.RESET_ALL}'   # Description
                f'{Fore.GREEN}{{bar}}{Style.RESET_ALL}'      # Progress bar
                f'{Fore.LIGHTBLACK_EX}{{r_bar}}{Style.RESET_ALL}'  # Info
            )
            request_iter = tqdm(
                new_requests_df.iterrows(),
                total=total_requests,
                desc=f'Processing Requests{Style.RESET_ALL}',
                unit='request',
                bar_format=bar_format,
                leave=True
            )
        else:
            request_iter = new_requests_df.iterrows()

        # Process requests individually
        for index, new_request in request_iter:
            try:
                # Convert row to dictionary
                new_request_dict = new_request.to_dict()
                request_id = new_request_dict.get('RequestID', 'Unknown')

                # Detect abuse and get feature values
                prediction, probability, feature_values = detect_abuse(
                    new_request_dict,
                    clf,
                    feature_cols,
                    pattern,
                    vulnerable_templates,
                    validity_threshold,
                    templates_requiring_approval,
                    authorized_client_auth_users,
                    training_mode,
                    disposition_categories,
                    return_features=True
                )

                # Apply custom classification threshold
                is_abuse = prediction == 1 and probability >= classification_threshold

                if is_abuse:
                    potential_abuses += 1
                    message = (
                        f"{Fore.RED}Potential abuse detected for Request ID {request_id} "
                        f"with probability {probability:.2f}{Style.RESET_ALL}"
                    )
                    logger.warning(message)

                    # Sanitize the request data before logging
                    sanitized_request_dict = sanitize_request_data(new_request_dict)

                    # Display detailed information
                    display_dict = sanitized_request_dict if args.redact else new_request_dict
                    logger.info(f"{Fore.WHITE}Requester Name: {Fore.LIGHTBLACK_EX}{display_dict['RequesterName']}{Style.RESET_ALL}")
                    logger.info(f"{Fore.WHITE}Certificate Subject: {Fore.LIGHTBLACK_EX}{display_dict['CertificateSubject']}{Style.RESET_ALL}")
                    logger.info(f"{Fore.WHITE}Certificate SANs: {Fore.LIGHTBLACK_EX}{display_dict['CertificateSANs']}{Style.RESET_ALL}")
                    logger.info(f"{Fore.WHITE}Issued Common Name: {Fore.LIGHTBLACK_EX}{display_dict['CertificateIssuedCommonName']}{Style.RESET_ALL}")
                    logger.info(f"{Fore.WHITE}EKUs: {Fore.LIGHTBLACK_EX}{display_dict['EnhancedKeyUsage']}{Style.RESET_ALL}")
                    logger.info(f"{Fore.WHITE}Request Date: {Fore.LIGHTBLACK_EX}{display_dict['RequestSubmissionTime']}{Style.RESET_ALL}")

                # Update progress bar postfix
                if use_progress_bar:
                    request_iter.set_postfix(Abuses=potential_abuses)

                # Feature contributions
                if args.show_features or is_abuse:
                    # Convert feature_values to DataFrame
                    feature_values_df = pd.DataFrame([feature_values])
                    feature_values_df = feature_values_df[feature_cols]

                    # Apply the scaler to the feature values
                    feature_values_scaled = scaler.transform(feature_values_df)

                    # Compute SHAP values
                    shap_values = explainer.shap_values(feature_values_scaled)

                    # Handle binary classification
                    shap_values_class = shap_values[1] if isinstance(shap_values, list) and len(shap_values) > 1 else shap_values[0]

                    # Extract SHAP values for the sample
                    shap_values_sample = shap_values_class[0]
                    shap_values_sample = np.reshape(shap_values_sample, -1)

                    shap_values_dict = dict(zip(feature_values_df.columns, shap_values_sample))

                    logger.debug(f"{Fore.YELLOW}Feature contributions for Request ID {request_id}:{Style.RESET_ALL}")
                    for feature_name in feature_values_df.columns:
                        feature_value = feature_values_df[feature_name].iloc[0]
                        shap_value = shap_values_dict.get(feature_name)
                        if shap_value is not None:
                            shap_value_scalar = float(shap_value)
                            logger.debug(
                                f"{Fore.LIGHTBLACK_EX}  {feature_name}: Value={feature_value}, "
                                f"Contribution={shap_value_scalar:.6f}{Style.RESET_ALL}"
                            )
                        else:
                            logger.warning(f"  {feature_name}: SHAP value not available.")

            except Exception as e:
                logger.error(f"Error processing Request ID {request_id}: {e}", exc_info=True)

        # Close the progress bar
        if use_progress_bar and isinstance(request_iter, tqdm):
            request_iter.close()

        # Summary of processing
        logger.info("Processing complete.")
        logger.info(f"Total requests processed: {total_requests}")
        logger.info(f"{Fore.RED}Potential abuses detected: {potential_abuses}{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperation cancelled by user. Exiting gracefully.{Style.RESET_ALL}")
        sys.exit(0)
    except FileNotFoundError as fnf_error:
        logger.error(f"File not found: {fnf_error}", exc_info=True)
        sys.exit(1)
    except ValueError as val_error:
        logger.error(f"Value error: {val_error}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()