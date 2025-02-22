# certifeye_utils.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Utility Functions
Author: glides
Version: 1.0

This module contains helper functions used across CertifEye scripts.
"""

import logging
import pandas as pd
import numpy as np
import re
import smtplib
from email.mime.text import MIMEText
from colorama import init, Fore, Style
import sys
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# === Configure Logging ===

logger = logging.getLogger('CertifEye-Utils')

# Define function to print ASCII banner
def print_banner():
    ascii_banner = f"""
{Fore.CYAN}
       ___         _   _  __ ___         
      / __|___ _ _| |_(_)/ _| __|  _ ___ 
     | (__/ -_) '_|  _| |  _| _| || / -_)
      \\___\\___|_|  \\__|_|_| |___\\_, \\___|
                                |__/     
{Style.RESET_ALL}
    """
    tagline = f"{Fore.YELLOW}CertifEye - An AD CS Abuse Detection Tool{Style.RESET_ALL}"
    author = f"{Fore.GREEN}Author: glides{Style.RESET_ALL}"
    version = f"{Fore.GREEN}Version: 1.0{Style.RESET_ALL}"

    print(ascii_banner)
    print(tagline)
    print()
    print(author)
    print(version)

# Custom TqdmLoggingHandler for console output
class TqdmLoggingHandler(logging.StreamHandler):
    """
    Custom logging handler to work with tqdm progress bars.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)

# === Helper Functions ===

def flag_privileged_entries(entry, pattern):
    """
    Flags entries that match privileged keywords.

    Args:
        entry (str): The entry to check.
        pattern (re.Pattern): Compiled regex pattern of privileged keywords.

    Returns:
        int: 1 if entry matches the pattern, 0 otherwise.
    """
    if pd.isnull(entry):
        return 0
    if pattern.search(str(entry)):
        return 1
    return 0

def is_user_account(requester_name):
    """
    Determines if the requester is a user account.

    Args:
        requester_name (str): The requester name.

    Returns:
        bool: True if it's a user account, False otherwise.
    """
    if isinstance(requester_name, str):
        return not requester_name.endswith('$')
    else:
        return False

def is_authorized_for_client_auth(requester_name, authorized_users):
    """
    Checks if the requester is authorized for client authentication.

    Args:
        requester_name (str): The requester name.
        authorized_users (list): List of authorized users.

    Returns:
        bool: True if authorized, False otherwise.
    """
    if isinstance(requester_name, str):
        return requester_name.lower() in authorized_users
    else:
        return False

def sanitize_request_data(request_data):
    """
    Sanitizes request data by removing sensitive fields.

    Args:
        request_data (dict): The request data.

    Returns:
        dict: Sanitized request data.
    """
    sanitized_data = request_data.copy()
    sensitive_fields = ['CertificateSubject', 'CertificateSANs', 'SerialNumber']
    for field in sensitive_fields:
        if field in sanitized_data:
            sanitized_data[field] = '[REDACTED]'
    return sanitized_data

def detect_abuse(
    request_data,
    clf,
    feature_cols,
    pattern,
    vulnerable_templates,
    validity_threshold,
    templates_requiring_approval,
    authorized_client_auth_users,
    training_mode,
    disposition_categories,
    return_features=False
):
    """
    Detects potential abuse in a certificate request.

    Args:
        request_data (dict): The request data.
        clf (sklearn.pipeline.Pipeline): Trained model pipeline.
        feature_cols (list): List of feature columns.
        pattern (re.Pattern): Compiled regex pattern of privileged keywords.
        vulnerable_templates (list): List of vulnerable templates.
        validity_threshold (float): Threshold for unusual validity periods.
        templates_requiring_approval (list): Templates that require approval.
        authorized_client_auth_users (list): Authorized users for client auth.
        training_mode (str): Training mode ('supervised', 'unsupervised', or 'hybrid').
        disposition_categories (list): List of disposition categories used during training.
        return_features (bool): Whether to return feature values.

    Returns:
        tuple: (abuse_pred, abuse_prob, feature_values) or (abuse_pred, abuse_prob)
    """
    try:
        # Convert to DataFrame
        request_df = pd.DataFrame([request_data])

        # Replace missing values in critical fields with default values
        request_df.fillna({
            'RequesterName': '',
            'CertificateTemplate': '',
            'CertificateIssuedCommonName': '',
            'CertificateSubject': '',
            'CertificateValidityStart': '',
            'CertificateValidityEnd': '',
            'EnhancedKeyUsage': '',
            'CertificateSANs': ''
        }, inplace=True)

        # Handle multi-line 'CertificateSANs'
        request_df['CertificateSANs'] = request_df['CertificateSANs'].astype(str).str.replace('\n', ' ').str.replace('\r', ' ')

        # === Feature Engineering ===

        # Privileged Entry Flags
        request_df['Privileged_IssuedCN'] = request_df['CertificateIssuedCommonName'].apply(
            flag_privileged_entries, args=(pattern,))
        request_df['Privileged_CertificateSubject'] = request_df['CertificateSubject'].apply(
            flag_privileged_entries, args=(pattern,))
        request_df['Privileged_CertificateSANs'] = request_df['CertificateSANs'].apply(
            flag_privileged_entries, args=(pattern,))

        # Time-based Features
        request_df['RequestSubmissionTime'] = pd.to_datetime(request_df['RequestSubmissionTime'], errors='coerce')
        if pd.isnull(request_df['RequestSubmissionTime']).any():
            request_df['RequestHour'] = 0
            request_df['Is_Off_Hours'] = 0
            request_df['RequestWindow'] = pd.to_datetime('1970-01-01')
        else:
            request_df['RequestHour'] = request_df['RequestSubmissionTime'].dt.hour
            off_hours_start = 19  # Should match the value used during training
            off_hours_end = 7     # Should match the value used during training
            request_df['Is_Off_Hours'] = request_df['RequestHour'].apply(
                lambda x: 1 if x >= off_hours_start or x < off_hours_end else 0
            )
            request_df['RequestWindow'] = request_df['RequestSubmissionTime'].dt.floor('h')

        # Validity Period
        request_df['CertificateValidityStart'] = pd.to_datetime(
            request_df['CertificateValidityStart'], errors='coerce')
        request_df['CertificateValidityEnd'] = pd.to_datetime(
            request_df['CertificateValidityEnd'], errors='coerce')
        request_df['CertificateValidityDuration'] = (
            request_df['CertificateValidityEnd'] - request_df['CertificateValidityStart']
        ).dt.days.fillna(0)
        request_df['Unusual_Validity_Period'] = request_df['CertificateValidityDuration'].apply(
            lambda x: 1 if x > validity_threshold else 0
        )

        # Vulnerable Template Flag
        request_df['Vulnerable_Template'] = request_df['CertificateTemplate'].apply(
            lambda x: 1 if x in vulnerable_templates else 0
        )

        # Disposition Status Encoding
        if 'RequestDisposition' in request_df.columns:
            request_df['RequestDisposition'] = request_df['RequestDisposition'].fillna('')
        else:
            request_df['RequestDisposition'] = ''

        # Perform one-hot encoding using the saved disposition categories
        for category in disposition_categories:
            column_name = f'Disposition_{category}'
            request_df[column_name] = (request_df['RequestDisposition'] == category).astype(int)
        # Drop the 'RequestDisposition' column as it's no longer needed
        request_df.drop('RequestDisposition', axis=1, inplace=True)

        # High Request Volume (Need to calculate 'Requests_Per_Hour' similar to training)
        # For a single request, we need to set 'High_Request_Volume' appropriately
        # Since we likely don't have historical data here, we can set it to 0
        # Alternatively, we can modify our approach for this feature
        request_df['Requests_Per_Hour'] = 1  # Default to 1 for new request
        request_volume_threshold = 50  # Should match the threshold used during training
        request_df['High_Request_Volume'] = 0  # Default to 0 unless you have data to compute it

        # Ensure all expected columns are present
        missing_cols = [col for col in feature_cols if col not in request_df.columns]
        if missing_cols:
            for col in missing_cols:
                request_df[col] = 0  # Add missing columns with default value of 0

        # Reorder columns to match feature_cols
        request_df = request_df[feature_cols]

        # Select features
        request_X = request_df.copy()

        # Handle missing or infinite values
        request_X.replace([np.inf, -np.inf], np.nan, inplace=True)
        request_X.fillna(0, inplace=True)

        if training_mode in ['supervised', 'hybrid']:
            # Predict abuse
            abuse_prob = clf.predict_proba(request_X)[:, 1]
            abuse_pred = clf.predict(request_X)
            if return_features:
                feature_values = request_X.iloc[0].to_dict()
                return abuse_pred[0], abuse_prob[0], feature_values
            else:
                return abuse_pred[0], abuse_prob[0]
        else:
            # Unsupervised prediction
            anomaly_score = clf.decision_function(request_X)
            abuse_pred = 1 if anomaly_score[0] < 0 else 0
            abuse_prob = -anomaly_score[0]
            if return_features:
                feature_values = request_X.iloc[0].to_dict()
                return abuse_pred, abuse_prob, feature_values
            else:
                return abuse_pred, abuse_prob

    except Exception as e:
        logger.error(f"Error in detect_abuse function: {e}", exc_info=True)
        if return_features:
            return None, None, None
        else:
            return None, None

def send_alert(email_recipient, request_data, probability, smtp_config):
    """
    Sends an email alert for a detected abuse.

    Args:
        email_recipient (str): Recipient email address.
        request_data (dict): Request data.
        probability (float): Probability of abuse.
        smtp_config (dict): SMTP configuration.

    Returns:
        None
    """
    sanitized_data = sanitize_request_data(request_data)
    msg_content = f"""
    Potential ESC abuse detected.
    Anomaly Score: {probability:.2f}
    Details:
    {sanitized_data}
    """
    msg = MIMEText(msg_content)
    msg['Subject'] = 'CertifEye ESC Abuse Alert'
    msg['From'] = smtp_config['sender_email']
    msg['To'] = email_recipient

    try:
        server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
        server.starttls()
        server.login(smtp_config['username'], smtp_config['password'])
        server.send_message(msg)
        server.quit()
        logger.info(f"Alert sent to {email_recipient}")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error occurred: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Failed to send alert: {e}", exc_info=True)
