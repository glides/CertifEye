#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - AD CS Abuse Detection Module
Author: glides
Version: 0.9.2

This script detects potential abuses of Active Directory Certificate Services,
including both known abuses and anomalies.
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
import scipy.special  # For logistic function
from datetime import datetime
from tqdm import tqdm
from colorama import init, Fore, Style
from certifeye_utils import (
    #detect_abuse,
    sanitize_request_data,
    TqdmLoggingHandler,
    load_config,
    get_logger,
    engineer_features,
)

# Initialize colorama
init(autoreset=True)

def get_parser():
    """
    Get the argument parser for the script.
    """
    parser = argparse.ArgumentParser(description='CertifEye - AD CS Abuse Detection Tool')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level (e.g., -v, -vv)')
    parser.add_argument('-r', '--redact', action='store_true', help='Redact sensitive data in logs/output')
    parser.add_argument('-f', '--show-features', action='store_true', help='Show feature contributions and explanations for detections')
    parser.add_argument('-i', '--request-id', type=str, help='Request ID(s) to analyze, separated by commas')
    return parser

def main(args=None):
    """
    Main function to execute the abuse detection process.
    """
    # === Configure Logging ===
    logger = get_logger('CertifEye-DetectAbuse')

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
        # === Load Configuration ===
        config = load_config()

        # Paths
        ca_logs_detection_path = config['paths']['ca_logs_detection_path']
        model_output_path = config['paths']['model_output_path']
        params_output_path = config['paths']['params_output_path']

        # Custom Classification Threshold
        classification_threshold = config.get('classification_threshold', 0.5)  # Default to 0.5 if not set

        # Load Trained Model and Parameters
        logger.info(f"Loading trained model from: {model_output_path}")
        clf = joblib.load(model_output_path)

        logger.info(f"Loading parameters from: {params_output_path}")
        with open(params_output_path, 'rb') as f:
            params = pickle.load(f)

        # Extract parameters
        feature_cols = params['feature_cols']
        validity_threshold = params['validity_threshold']
        training_mode = params.get('training_mode', 'supervised')
        pattern = params['pattern']
        vulnerable_templates = params['vulnerable_templates']
        templates_requiring_approval = params.get('templates_requiring_approval', [])
        authorized_client_auth_users = params.get('authorized_client_auth_users', [])
        authorized_client_auth_users = [user.lower() for user in authorized_client_auth_users]
        algorithm = params.get('algorithm', 'random_forest')

        # Extract scaler and classifier from the pipeline
        scaler = clf.named_steps['scaler']
        classifier = clf.named_steps.get('classifier') or clf.named_steps.get('isolation_forest')

        # === Load SHAP Explainer ===
        explainer = shap.TreeExplainer(classifier)

        # === Load New Requests from CSV ===
        logger.info(f"Loading CA logs for detection from: {ca_logs_detection_path}")
        try:
            detection_df = pd.read_csv(
                ca_logs_detection_path,
                quoting=csv.QUOTE_MINIMAL,
                engine='python',
                sep=','
            )
        except ValueError as ve:
            logger.warning(f"Error reading CSV with 'python' engine: {ve}")
            logger.info("Attempting to read the CSV without specifying the engine.")
            detection_df = pd.read_csv(
                ca_logs_detection_path,
                quoting=csv.QUOTE_MINIMAL,
                sep=','
            )

        # Handle multi-line fields in 'CertificateSANs'
        if 'CertificateSANs' in detection_df.columns:
            detection_df['CertificateSANs'] = detection_df['CertificateSANs'].astype(str).str.replace('\n', ' ').str.replace('\r', ' ')

        # Check if DataFrame is empty
        if detection_df.empty:
            logger.warning("No new requests to process.")
            return

        if args.request_id:
            # Analyze specific requests by Request ID(s)
            request_ids = [int(rid.strip()) for rid in args.request_id.split(',')]
            specific_requests = detection_df[detection_df['RequestID'].isin(request_ids)]
            if specific_requests.empty:
                logger.error(f"Request ID(s) {args.request_id} not found.")
                return
            detection_df = specific_requests

        total_requests = len(detection_df)
        logger.info(f"Processing {total_requests} new certificate requests.")

        potential_abuses = 0  # Counter for detected abuses

        # Use progress bar if not showing features for all requests and not analyzing specific requests
        use_progress_bar = not args.show_features and not args.request_id

        if use_progress_bar:
            bar_format = '{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
            request_iter = tqdm(
                detection_df.iterrows(),
                total=total_requests,
                desc='Processing Requests',
                unit='request',
                bar_format=bar_format,
                leave=True
            )
        else:
            request_iter = detection_df.iterrows()

        # Process requests individually
        for index, new_request in request_iter:
            try:
                # Convert row to DataFrame for consistent processing
                new_request_df = pd.DataFrame([new_request])

                # Engineer features using the shared function
                feature_values_df = engineer_features(
                    new_request_df,
                    feature_cols,
                    validity_threshold,
                    pattern,
                    vulnerable_templates,
                    templates_requiring_approval,
                    authorized_client_auth_users,
                    training_mode,
                    detection_mode=True  # Indicates we're in detection mode
                )

                # Save the original Request ID
                request_id = new_request_df['RequestID'].iloc[0]

                # Handle missing or infinite values
                feature_values_df.replace([np.inf, -np.inf], np.nan, inplace=True)
                feature_values_df.fillna(0, inplace=True)

                # Apply the scaler to the feature values
                feature_values_scaled = scaler.transform(feature_values_df)

                # Predict abuse
                if hasattr(classifier, 'predict_proba'):
                    probabilities = classifier.predict_proba(feature_values_scaled)
                    class_index = np.where(classifier.classes_ == 1)[0][0]
                    probability = probabilities[0, class_index]
                    prediction = int(probability >= classification_threshold)
                else:
                    # For models that do not support predict_proba
                    prediction = classifier.predict(feature_values_scaled)[0]
                    probability = 0.5  # Placeholder

                is_abuse = prediction == 1

                # Explanations list
                explanations = []

                # Rule-based override
                if feature_values_df['Privileged_and_Vulnerable'].iloc[0] == 1:
                    is_abuse = True
                    probability = 1.0
                    explanations.append("Use of vulnerable template combined with privileged keywords detected (Rule-based detection).")
                    logger.info("Rule-based override: High-risk combination detected.")

                # Logic to exclude or include certain requests based on business rules
                requester_name = new_request['RequesterName'].lower()
                issued_cn = str(new_request['CertificateIssuedCommonName']).lower()
                certificate_subject = str(new_request['CertificateSubject']).lower()
                certificate_sans = str(new_request['CertificateSANs']).lower()

                if requester_name == issued_cn and not pattern.search(issued_cn):
                    is_abuse = False  # Likely a normal self-enrollment
                    explanations.append("Requester name matches issued CN without privileged keywords; likely benign.")

                if is_abuse:
                    potential_abuses += 1

                    message = (
                        f"Potential abuse detected for Request ID {request_id} "
                        f"with probability {probability:.2f}"
                    )
                    logger.warning(message)

                    # Sanitize the request data before logging
                    sanitized_request_dict = sanitize_request_data(new_request.to_dict())

                    # Display detailed information
                    display_dict = sanitized_request_dict if args.redact else new_request.to_dict()
                    logger.info(f"Requester Name: {display_dict['RequesterName']}")
                    logger.info(f"Certificate Subject: {display_dict['CertificateSubject']}")
                    logger.info(f"Certificate SANs: {display_dict['CertificateSANs']}")
                    logger.info(f"Issued Common Name: {display_dict['CertificateIssuedCommonName']}")
                    logger.info(f"Certificate Template: {display_dict['CertificateTemplate']}")
                    logger.info(f"Enhanced Key Usage: {display_dict['EnhancedKeyUsage']}")
                    logger.info(f"Request Date: {display_dict['RequestSubmissionTime']}")

                    # Generate human-readable explanation if requested
                    if args.show_features or args.verbose:
                        # Compute SHAP values
                        shap_values = explainer.shap_values(feature_values_scaled)
                        shap_values_sample = shap_values[0] if isinstance(shap_values, list) else shap_values
                        base_value = explainer.expected_value[0] if isinstance(explainer.expected_value, list) else explainer.expected_value

                        # Feature contributions (in log-odds)
                        logger.info(f"Feature contributions for Request ID {request_id}:")

                        for feature_name, shap_value in zip(feature_values_df.columns, shap_values_sample[0]):
                            feature_value = feature_values_df[feature_name].iloc[0]
                            abs_shap_value = abs(shap_value)

                            # Generate explanations based on significant features
                            if abs_shap_value > 0.05:  # Threshold can be adjusted
                                if feature_name == 'Privileged_and_Vulnerable' and feature_value == 1:
                                    explanations.append("Use of a vulnerable template combined with privileged keywords in certificate details.")
                                elif feature_name == 'Is_Off_Hours' and feature_value == 1:
                                    explanations.append("Certificate request submitted during off-hours.")
                                elif feature_name == 'Unusual_Validity_Period' and feature_value == 1:
                                    explanations.append("Certificate has an unusually long validity period.")
                                elif feature_name == 'High_Request_Volume' and feature_value == 1:
                                    explanations.append("High volume of requests from the requester in the last 24 hours.")
                                # Add explanations for other features as needed

                            # Log feature contributions
                            logger.info(
                                f"  {feature_name}: Value={feature_value}, Contribution={shap_value:.5f}"
                            )

                        # Total probability contribution
                        predicted_log_odds = base_value + shap_values_sample[0].sum()
                        predicted_prob = scipy.special.expit(predicted_log_odds)

                        logger.info(f"Predicted Probability: {predicted_prob:.5f}")

                    # Combine explanations
                    if explanations:
                        explanation_text = "The request was flagged because:\n- " + "\n- ".join(explanations)
                        logger.info(f"{Fore.YELLOW}Explanation: {explanation_text}{Style.RESET_ALL}")

                # Update progress bar postfix
                if use_progress_bar:
                    request_iter.set_postfix(Abuses=potential_abuses)

            except Exception as e:
                logger.error(f"Error processing Request ID {request_id}: {e}", exc_info=args.verbose >= 1)
                if args.verbose >= 1:
                    import traceback
                    traceback.print_exc()
                continue  # Continue processing the next request

        # Close the progress bar
        if use_progress_bar and isinstance(request_iter, tqdm):
            request_iter.close()

        # Summary of processing
        logger.info("Processing complete.")
        logger.info(f"Total requests processed: {total_requests}")
        logger.info(f"Potential abuses detected: {potential_abuses}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Returning to console.")
        return
    except FileNotFoundError as fnf_error:
        logger.error(f"File not found: {fnf_error}", exc_info=args.verbose >= 1)
    except ValueError as val_error:
        logger.error(f"Value error: {val_error}", exc_info=args.verbose >= 1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=args.verbose >= 1)

if __name__ == '__main__':
    main()
