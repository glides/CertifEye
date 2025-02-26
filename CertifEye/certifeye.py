# certifeye.py
# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - AD CS Abuse Detection Script
Author: glides
Version: 0.9

This script detects potential abuses of Active Directory Certificate Services.
"""

import pandas as pd
import numpy as np
import re
import yaml
import joblib
import pickle
import logging
import argparse
import sys
import csv
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
import shap
from tqdm import tqdm
from colorama import init, Fore, Style
from certifeye_utils import (
    print_banner,
    detect_abuse,
    send_alert,
    sanitize_request_data,
    is_user_account,
    is_authorized_for_client_auth,
    TqdmLoggingHandler
)

# Initialize colorama
init(autoreset=True)

# === Parse Command-Line Arguments ===

parser = argparse.ArgumentParser(description='CertifEye - AD CS Abuse Detection Tool')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('-r', '--redact', action='store_true', help='Redact sensitive data in logs/output')
parser.add_argument('-f', '--show-features', action='store_true', help='Show feature contributions for all requests')
args = parser.parse_args()

# === Configure Logging ===

# Create logger
logger = logging.getLogger('CertifEye')
logger.setLevel(logging.DEBUG)

# Create handlers
file_handler = logging.FileHandler('certifeye.log')
file_handler.setLevel(logging.INFO)

# Custom TqdmLoggingHandler for console output
console_handler = TqdmLoggingHandler()
console_handler.setLevel(logging.INFO)  # Display INFO and above messages by default

# Create formatters and add them to handlers
file_formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
console_formatter = logging.Formatter('%(message)s')

file_handler.setFormatter(file_formatter)
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Adjust console logging level based on verbosity
if args.verbose:
    console_handler.setLevel(logging.DEBUG)

# === Main Execution ===

if __name__ == '__main__':
    try:
        print_banner()

        # === Load Configuration ===

        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)

        # Paths
        ca_logs_detection_path = config['paths']['ca_logs_detection_path']
        model_output_path = config['paths']['model_output_path']
        params_output_path = config['paths']['params_output_path']

        # SMTP Configuration
        smtp_config = config.get('smtp', {})

        # Custom Classification Threshold
        classification_threshold = config.get('classification_threshold', 0.5)  # Default to 0.5 if not set

        # Load Trained Model and Parameters
        logger.info(f"{Fore.WHITE}Loading trained model from: {Fore.LIGHTBLACK_EX}%s{Style.RESET_ALL}", model_output_path)
        clf = joblib.load(model_output_path)

        logger.info(f"{Fore.WHITE}Loading parameters from: {Fore.LIGHTBLACK_EX}%s{Style.RESET_ALL}", params_output_path)
        with open(params_output_path, 'rb') as f:
            params = pickle.load(f)

        feature_cols = params['feature_cols']
        validity_threshold = params['validity_threshold']
        training_mode = params.get('training_mode', 'supervised')
        disposition_categories = params.get('disposition_categories', [])  # Get disposition categories

        # Privileged Keywords
        pattern = params['pattern']

        # Other Parameters
        vulnerable_templates = params['vulnerable_templates']
        templates_requiring_approval = params.get('templates_requiring_approval', [])
        authorized_client_auth_users = params.get('authorized_client_auth_users', [])
        authorized_client_auth_users = [user.lower() for user in authorized_client_auth_users]

        # Extract scaler and classifier from the pipeline
        scaler = clf.named_steps['scaler']
        classifier = clf.named_steps['classifier']

        # === Check the Classes Known to the Classifier ===
        logger.debug(f"Classifier classes: {classifier.classes_}")

        # === Load SHAP Explainer ===
        # Initialize the SHAP TreeExplainer with the classifier
        explainer = shap.TreeExplainer(classifier)

        # === Load New Requests from CSV ===

        logger.info(f"{Fore.WHITE}Loading CA logs for detection from: {Fore.LIGHTBLACK_EX}%s{Style.RESET_ALL}", ca_logs_detection_path)

        # Read the CSV file
        try:
            new_requests_df = pd.read_csv(
                ca_logs_detection_path,
                quoting=csv.QUOTE_MINIMAL,
                escapechar='\\',
                engine='python',
                sep=','
            )
        except ValueError as ve:
            # If custom line terminators are not supported, remove 'engine' parameter
            logger.warning("Error reading CSV with 'python' engine: %s", ve)
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
        else:
            total_requests = len(new_requests_df)
            logger.info(f"{Fore.CYAN}Processing {total_requests} new certificate requests.{Style.RESET_ALL}")

            potential_abuses = 0  # Counter for detected abuses

            # Decide whether to use the progress bar based on the -f flag
            use_progress_bar = not args.show_features

            if use_progress_bar:
                # Custom bar format with different colors
                bar_format = (
                    f'{Fore.YELLOW}{{l_bar}}{Style.RESET_ALL}'  # Description in yellow
                    f'{Fore.GREEN}{{bar}}{Style.RESET_ALL}'     # Progress bar in green
                    f'{Fore.LIGHTBLACK_EX}{{r_bar}}{Style.RESET_ALL}'    # Right part (percentage, time, postfix) in grey
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
                        disposition_categories,  # Pass disposition_categories
                        return_features=True
                    )

                    # Apply custom classification threshold
                    if probability >= classification_threshold:
                        is_abuse = prediction == 1
                    else:
                        is_abuse = False

                    if is_abuse:
                        potential_abuses += 1
                        message = (f"{Fore.RED}Potential abuse detected for Request ID {request_id} "
                                   f"with probability {probability:.2f}{Style.RESET_ALL}")
                        logger.warning(message)

                        # Sanitize the request data before printing
                        sanitized_request_dict = sanitize_request_data(new_request_dict)

                        if args.redact:
                            # Print out the sanitized requester of the certificate and the Subject, SAN, Common Name, EKUs, and Request Date
                            logger.info(f"{Fore.WHITE}Requester Name: {Fore.LIGHTBLACK_EX}{sanitized_request_dict['RequesterName']}{Style.RESET_ALL}")
                            logger.info(f"{Fore.WHITE}Certificate Subject: {Fore.LIGHTBLACK_EX}{sanitized_request_dict['CertificateSubject']}{Style.RESET_ALL}")
                            logger.info(f"{Fore.WHITE}Certificate SANs: {Fore.LIGHTBLACK_EX}{sanitized_request_dict['CertificateSANs']}{Style.RESET_ALL}")
                            logger.info(f"{Fore.WHITE}Issued Common Name: {Fore.LIGHTBLACK_EX}{sanitized_request_dict['CertificateIssuedCommonName']}{Style.RESET_ALL}")
                            #logger.info(f"Template: {sanitized_request_dict['CertificateTemplate']}")
                            #logger.info(f"Valid From: {sanitized_request_dict['CertificateValidityStart']}")
                            #logger.info(f"Valid To: {sanitized_request_dict['CertificateValidityEnd']}")
                            logger.info(f"{Fore.WHITE}EKUs: {Fore.LIGHTBLACK_EX}{sanitized_request_dict['EnhancedKeyUsage']}{Style.RESET_ALL}")
                            #logger.info(f"Disposition: {sanitized_request_dict['RequestDisposition']}")
                            logger.info(f"{Fore.WHITE}Request Date: {Fore.LIGHTBLACK_EX}{sanitized_request_dict['RequestSubmissionTime']}{Style.RESET_ALL}")
                        else:
                            # Print out the requester of the certificate and the Subject, SAN, Common Name, Template, Validity, EKUs, Disposition, and Request Date
                            logger.info(f"{Fore.WHITE}Requester Name: {Fore.LIGHTBLACK_EX}{new_request_dict['RequesterName']}{Style.RESET_ALL}")
                            logger.info(f"{Fore.WHITE}Certificate Subject: {Fore.LIGHTBLACK_EX}{new_request_dict['CertificateSubject']}{Style.RESET_ALL}")
                            logger.info(f"{Fore.WHITE}Certificate SANs: {Fore.LIGHTBLACK_EX}{new_request_dict['CertificateSANs']}{Style.RESET_ALL}")
                            logger.info(f"{Fore.WHITE}Issued Common Name: {Fore.LIGHTBLACK_EX}{new_request_dict['CertificateIssuedCommonName']}{Style.RESET_ALL}")
                            #logger.info(f"Template: {new_request_dict['CertificateTemplate']}")
                            #logger.info(f"Valid From: {new_request_dict['CertificateValidityStart']}")
                            #logger.info(f"Valid To: {new_request_dict['CertificateValidityEnd']}")
                            logger.info(f"{Fore.WHITE}EKUs: {Fore.LIGHTBLACK_EX}{new_request_dict['EnhancedKeyUsage']}{Style.RESET_ALL}")
                            #logger.info(f"Disposition: {new_request_dict['RequestDisposition']}")
                            logger.info(f"{Fore.WHITE}Request Date: {Fore.LIGHTBLACK_EX}{new_request_dict['RequestSubmissionTime']}{Style.RESET_ALL}")

                            


                            

                    # Update the progress bar postfix with the current abuse count
                    if use_progress_bar:
                                request_iter.set_postfix(Abuses=potential_abuses)

                    # Feature contributions
                    if args.show_features or is_abuse:
                        # Convert feature_values to DataFrame
                        feature_values_df = pd.DataFrame([feature_values])

                        # Ensure feature order is consistent
                        feature_values_df = feature_values_df[feature_cols]

                        # Apply the scaler to the feature values
                        feature_values_scaled = scaler.transform(feature_values_df)

                        # Compute SHAP values
                        shap_values = explainer.shap_values(feature_values_scaled)

                        # Handle cases with different number of classes
                        if isinstance(shap_values, list):
                            if len(shap_values) == 1:
                                # Single class (possibly in regression)
                                shap_values_class = shap_values[0]
                            elif len(shap_values) == 2:
                                # Binary classification: use index 1 for positive class
                                shap_values_class = shap_values[1]
                            else:
                                # Multiclass classification
                                shap_values_class = shap_values[1]  # Adjust as needed
                        else:
                            shap_values_class = shap_values  # For regression or single output

                        # Extract shap values for the first (and only) sample
                        shap_values_sample = shap_values_class[0]

                        # Ensure shap_values_sample is a 1D array
                        shap_values_sample = np.reshape(shap_values_sample, -1)

                        shap_values_dict = dict(zip(feature_values_df.columns, shap_values_sample))

                        # Output detailed feature contributions in grey
                        logger.debug(f"{Fore.YELLOW}Feature contributions for Request ID {request_id}:{Style.RESET_ALL}")
                        for feature_name in feature_values_df.columns:
                            feature_value = feature_values_df[feature_name].iloc[0]
                            shap_value = shap_values_dict.get(feature_name)
                            if shap_value is not None:
                                # Ensure shap_value is a scalar float
                                shap_value_scalar = float(shap_value)
                                # Output in grey
                                logger.debug(f"{Fore.LIGHTBLACK_EX}  {feature_name}: Value={feature_value}, Contribution={shap_value_scalar:.6f}{Style.RESET_ALL}")
                            else:
                                logger.warning(f"  {feature_name}: SHAP value not available.")

                    elif args.verbose:
                        pass
                        # If verbose mode is on, log non-abuse cases if desired (this is spammy)
                        # logger.debug(f"No abuse detected for Request ID {request_id}.")

                except Exception as e:
                    logger.error(f"Error processing Request ID {request_id}: {e}", exc_info=True)

            # Close the progress bar if it was used
            if use_progress_bar and isinstance(request_iter, tqdm):
                request_iter.close()

            # Summary of processing
            logger.info("Processing complete.")
            logger.info("Total requests processed: %d", total_requests)
            logger.info(f"{Fore.RED}Potential abuses detected: {potential_abuses}{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperation cancelled by user. Exiting gracefully.{Style.RESET_ALL}")
        sys.exit(0)
    except FileNotFoundError as fnf_error:
        logger.error(f"File not found: {fnf_error}", exc_info=True)
    except ValueError as val_error:
        logger.error(f"Value error: {val_error}", exc_info=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
