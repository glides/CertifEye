#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Utility Functions
Author: glides
Version: 0.9.2

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
import yaml
from tqdm import tqdm
from datetime import datetime
import os
import hashlib
import math

# Initialize colorama
init(autoreset=True)

# === Configure Logging ===

def get_logger(name):
    """
    Configures and returns a logger with the specified name.

    Args:
        name (str): Name of the logger.

    Returns:
        logging.Logger: Configured logger.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)

        # File handler
        file_handler = logging.FileHandler(f'{name}.log')
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

    return logger

# === ASCII Banner Function ===

def print_banner():
    """
    Prints the ASCII art banner for CertifEye.
    """
    ascii_banner = f"""
{Fore.CYAN}
{Fore.CYAN}   ___         _   _  __{Fore.YELLOW} ___         
{Fore.CYAN}  / __|___ _ _| |_(_)/ _{Fore.YELLOW}| __|  _ ___ 
{Fore.CYAN} | (__/ -_) '_|  _| |  _{Fore.YELLOW}| _| || / -_)
{Fore.CYAN}  \\___\\___|_|  \\__|_|_|{Fore.YELLOW} |___\\_, \\___|
{Fore.CYAN}                        {Fore.YELLOW}    |__/     
{Style.RESET_ALL}
    """
    tagline = f"{Fore.CYAN}Certif{Fore.YELLOW}Eye{Style.RESET_ALL} -{Fore.LIGHTBLACK_EX} An AD CS Abuse Detection Tool\n{Style.RESET_ALL}"
    author = f"{Fore.WHITE}Author: {Fore.LIGHTBLACK_EX}glides <glid3s@protonmail.com>{Style.RESET_ALL}"
    version = f"{Fore.WHITE}Version: {Fore.LIGHTBLACK_EX}0.9.2\n{Style.RESET_ALL}"

    print(ascii_banner)
    print(tagline)
    print(author)
    print(version)

# === Custom Logging Handler for TQDM Compatibility ===

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

# === Configuration Loading Function ===

def load_config(config_path='config.yaml'):
    """
    Loads the configuration from a YAML file, handling environment variables.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        dict: Configuration dictionary.
    """
    try:
        with open(config_path, 'r') as file:
            # Use yaml.SafeLoader to avoid arbitrary code execution
            # Handle environment variables in the config
            class EnvVarLoader(yaml.SafeLoader):
                pass

            # Add a constructor for environment variables
            def env_var_constructor(loader, node):
                value = loader.construct_scalar(node)
                if value.startswith('${') and value.endswith('}'):
                    env_var = value[2:-1]
                    return os.getenv(env_var)
                else:
                    return value

            EnvVarLoader.add_constructor('!ENV', env_var_constructor)

            config = yaml.load(file, Loader=EnvVarLoader)
        return config
    except FileNotFoundError:
        print(f"{Fore.RED}Configuration file {config_path} not found.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error loading configuration: {e}{Style.RESET_ALL}")
        sys.exit(1)

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
        return requester_name.lower() in [user.lower() for user in authorized_users]
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

def parse_dates(df, date_columns):
    """
    Parses date columns in a DataFrame.

    Args:
        df (pd.DataFrame): The DataFrame containing date columns.
        date_columns (list): List of date column names.

    Returns:
        pd.DataFrame: DataFrame with parsed dates.
    """
    for col in date_columns:
        df[col] = pd.to_datetime(df[col], errors='coerce')
    return df

def calculate_entropy(s):
    """
    Calculates the Shannon entropy of a string.

    Args:
        s (str): Input string.

    Returns:
        float: Entropy value.
    """
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

# === Additional Utility Functions ===

def setup_logging(level=logging.INFO):
    """
    Sets up the logging configuration for scripts.

    Args:
        level (int): Logging level.

    Returns:
        None
    """
    logger = logging.getLogger('CertifEye')
    logger.setLevel(level)
    if not logger.handlers:
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # Prevent duplicate logs
    logger.propagate = False

def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Handles uncaught exceptions by logging them.

    Args:
        exc_type: Exception type.
        exc_value: Exception value.
        exc_traceback: Exception traceback.

    Returns:
        None
    """
    logger = logging.getLogger('CertifEye')
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

# Register the exception handler
sys.excepthook = handle_exception

def engineer_features(
    df,
    feature_cols,
    validity_threshold,
    pattern,
    vulnerable_templates,
    templates_requiring_approval,
    authorized_client_auth_users,
    training_mode,
    detection_mode=False
):
    """
    Engineer features from the given DataFrame.

    Args:
        df (pd.DataFrame): The input DataFrame.
        feature_cols (list): List of feature column names.
        validity_threshold (float): Threshold for unusual validity periods.
        pattern (re.Pattern): Compiled regex pattern for privileged keywords.
        vulnerable_templates (list): List of vulnerable certificate templates.
        templates_requiring_approval (list): Templates that require approval.
        authorized_client_auth_users (list): List of authorized users.
        training_mode (str): Training mode ('supervised' or 'unsupervised').
        detection_mode (bool): Indicates if the function is used for detection.

    Returns:
        pd.DataFrame: DataFrame containing engineered features.
    """
    logger = logging.getLogger('CertifEye-Utils')

    # Initialize feature values
    df_features = pd.DataFrame()

    # Privileged Account Flagging
    df_features['Privileged_IssuedCN'] = df['CertificateIssuedCommonName'].apply(
        flag_privileged_entries, args=(pattern,)
    )
    df_features['Privileged_CertificateSubject'] = df['CertificateSubject'].apply(
        flag_privileged_entries, args=(pattern,)
    )
    df_features['Privileged_CertificateSANs'] = df['CertificateSANs'].apply(
        flag_privileged_entries, args=(pattern,)
    )

    # Vulnerable Template Flag
    df_features['Vulnerable_Template'] = df['CertificateTemplate'].apply(
        lambda x: 1 if x in vulnerable_templates else 0
    )

    # Interaction Feature: Privileged and Vulnerable
    df_features['Privileged_and_Vulnerable'] = (
        df_features['Vulnerable_Template'] &
        (
            df_features['Privileged_IssuedCN'] |
            df_features['Privileged_CertificateSubject'] |
            df_features['Privileged_CertificateSANs']
        )
    ).astype(int)

    # Time-Based Features
    df['RequestSubmissionTime'] = pd.to_datetime(df['RequestSubmissionTime'], errors='coerce')
    df['RequestHour'] = df['RequestSubmissionTime'].dt.hour
    df_features['Is_Off_Hours'] = df['RequestHour'].apply(
        lambda x: 1 if x >= 19 or x < 7 else 0
    )

    # Validity Period Anomalies
    df['CertificateValidityStart'] = pd.to_datetime(df['CertificateValidityStart'], errors='coerce')
    df['CertificateValidityEnd'] = pd.to_datetime(df['CertificateValidityEnd'], errors='coerce')
    df['CertificateValidityDuration'] = (
        df['CertificateValidityEnd'] - df['CertificateValidityStart']
    ).dt.days
    df_features['Unusual_Validity_Period'] = df['CertificateValidityDuration'].apply(
        lambda x: 1 if x > validity_threshold else 0
    )

    # Disposition Status Encoding
    df_features['Disposition_Issued'] = df['RequestDisposition'].apply(
        lambda x: 1 if str(x).strip().lower() == 'issued' else 0
    )

    # Requester Behavior Analysis
    if detection_mode:
        # Placeholder values for detection mode
        df_features['High_Request_Volume'] = 0
        df_features['Requests_Last_24h'] = 0.0
    else:
        # Compute 'Requests_Last_24h' and 'High_Request_Volume' for training
        df = df.sort_values(['RequesterName', 'RequestSubmissionTime'])
        df.set_index('RequestSubmissionTime', inplace=True)
        df['Requests_Last_24h'] = (
            df.groupby('RequesterName')['RequestID']
            .rolling('24h')
            .count()
            .reset_index(level=0, drop=True)
        )
        df.reset_index(inplace=True)
        df['Requests_Last_24h'] = df['Requests_Last_24h'].fillna(0)
        request_volume_threshold = (
            df['Requests_Last_24h'].mean()
            + 3 * df['Requests_Last_24h'].std()
        )
        df_features['High_Request_Volume'] = df['Requests_Last_24h'].apply(
            lambda x: 1 if x > request_volume_threshold else 0
        )
        df_features['Requests_Last_24h'] = df['Requests_Last_24h']

    # Field Length Features
    df_features['Subject_Length'] = df['CertificateSubject'].apply(
        lambda x: len(str(x)) if pd.notnull(x) else 0
    )
    df_features['SAN_Length'] = df['CertificateSANs'].apply(
        lambda x: len(str(x)) if pd.notnull(x) else 0
    )

    # Entropy Features
    df_features['Subject_Entropy'] = df['CertificateSubject'].apply(
        lambda x: calculate_entropy(str(x)) if pd.notnull(x) else 0
    )
    df_features['SAN_Entropy'] = df['CertificateSANs'].apply(
        lambda x: calculate_entropy(str(x)) if pd.notnull(x) else 0
    )

    # Ensure all expected columns are present
    for col in feature_cols:
        if col not in df_features.columns:
            df_features[col] = 0  # Add missing columns with default value of 0

    # Reorder columns to match the feature_cols
    df_features = df_features[feature_cols]

    return df_features
