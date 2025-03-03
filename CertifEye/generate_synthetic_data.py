#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Synthetic CA Log Data Generator with Enhanced Anomaly Generation
Author: glides
Version: 0.9.2

This script generates synthetic CA log data similar in structure to you find in real logs,
without including any sensitive information. It generates training and detection datasets
with configurable numbers of known abuses and diverse anomaly cases.
"""

import random
import pandas as pd
import numpy as np
import argparse
import logging
import sys
from datetime import datetime, timedelta
from faker import Faker
from colorama import init, Fore, Style
from ruamel.yaml import YAML
from tqdm import tqdm

# Initialize Faker
fake = Faker()

# === Configuration ===

DOMAIN_NAME = "contoso.com"  # Use a consistent domain name
INTERNAL_DOMAIN = "intra.contoso.local"

# Certificate Templates and their EKUs
certificate_templates = {
    "UserCertificate": ["Client Authentication", "Secure Email"],
    "MachineCertificate": ["Client Authentication", "Server Authentication"],
    "AdminCertificate": ["Client Authentication", "Any Purpose"],
    "ServerCertificate": ["Server Authentication"],
    "EncryptionCertificate": ["Secure Email"],
    "VPNCertificate": ["Client Authentication"],
    "EmailCertificate": ["Secure Email"],
    "SMIMECertificate": ["Secure Email"],
    "CodeSigningCertificate": ["Code Signing"],
    "DomainControllerCertificate": ["Client Authentication", "Server Authentication"],
    "UnknownTemplate": ["UnknownUsage"],  # For anomaly generation
}

# Vulnerable Templates (Abuse Cases)
vulnerable_templates = [
    "AdminCertificate",
    "DomainControllerCertificate",
    "CodeSigningCertificate",
    "ESC1"
]

# Request Dispositions
request_dispositions = ["Issued", "Pending", "Denied", "Revoked"]

# Privileged Keywords
privileged_keywords = [
    "Admin",
    "Administrator",
    "Root",
    "System",
    "Service",
    "Backup",
    "Security",
    "DomainAdmin",
    "EnterpriseAdmin"
]

# Departments for machine names
departments = ["Sales", "Marketing", "Engineering", "HR", "Finance", "IT", "Legal", "Operations"]

# EKUs indicative of potential abuse
abuse_ekus = [
    "Client Authentication",
    "Smart Card Logon",
    "PKINIT Client Authentication",
    "Any Purpose",
    "SubCA",
    "Code Signing",
    "UnknownUsage"
]

def get_parser():
    parser = argparse.ArgumentParser(description='CertifEye - Synthetic Data Generator')
    parser.add_argument('-tr', '--train_records', type=int, default=1000, help='Number of training records to generate')
    parser.add_argument('-ta', '--train_abuses', type=int, default=5, help='Number of known abuse cases for training')
    parser.add_argument('-dr', '--detect_records', type=int, default=5000, help='Number of detection records to generate')
    parser.add_argument('-da', '--detect_abuses', type=int, default=5, help='Number of known abuse cases for detection')
    parser.add_argument('-an', '--anomalies', type=int, default=50, help='Number of anomalies to generate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-u', '--update-config', action='store_true', help='Update config.yaml with generated data')
    return parser

def generate_username(first_name, last_name):
    # Choose a naming convention
    convention = random.choice(['first.last', 'firstlast', 'flast', 'firstl'])
    if convention == 'first.last':
        username = f"{first_name}.{last_name}".lower()
    elif convention == 'firstlast':
        username = f"{first_name}{last_name}".lower()
    elif convention == 'flast':
        username = f"{first_name[0]}{last_name}".lower()
    else:  # 'firstl'
        username = f"{first_name}{last_name[0]}".lower()
    return username

def generate_machine_name(department=None):
    # Machine naming convention: dept-abbreviation + sequential number
    dept = department[:3].lower() if department else 'gen'
    number = random.randint(100, 999)
    machine_name = f"{dept}-pc{number}"
    return machine_name

def generate_synthetic_ca_logs(num_records, num_abuses=0, num_anomalies=0, abuses_randomized=True, start_request_id=10000, label_anomalies=False):
    data = []
    known_abuse_request_ids = set()
    known_anomaly_request_ids = set()
    used_request_ids = set()

    base_request_id = start_request_id  # Starting RequestID
    base_serial_number = 1000000  # Starting SerialNumber

    total_records = num_records
    normal_records = total_records - num_abuses - num_anomalies

    # Generate unique RequestIDs for normal records
    normal_request_ids = random.sample(range(base_request_id, base_request_id + total_records * 2), normal_records)
    used_request_ids.update(normal_request_ids)

    # Generate normal records with progress bar
    for idx, request_id in tqdm(enumerate(normal_request_ids), total=len(normal_request_ids), desc="Generating Normal Records"):
        record = generate_normal_record(request_id, idx, base_serial_number)
        data.append(record)

    # Generate known abuse cases
    abuse_records, abuse_ids = generate_abuse_cases(
        num_abuses,
        used_request_ids,
        base_request_id,
        base_request_id + total_records * 2
    )
    known_abuse_request_ids.update(abuse_ids)
    data.extend(abuse_records)

    # Generate anomaly cases
    anomaly_records, anomaly_ids = generate_anomaly_cases(
        num_anomalies,
        used_request_ids,
        base_request_id,
        base_request_id + total_records * 2
    )
    known_anomaly_request_ids.update(anomaly_ids)
    data.extend(anomaly_records)

    # Create DataFrame
    df = pd.DataFrame(data)

    # Label anomalies as abuse if required
    if label_anomalies:
        df['Abuse_Flag'] = 0  # Initialize
        df.loc[df['RequestID'].isin(known_abuse_request_ids), 'Abuse_Flag'] = 1
        df.loc[df['RequestID'].isin(known_anomaly_request_ids), 'Abuse_Flag'] = 1

    if abuses_randomized:
        # Shuffle records
        df = df.sample(frac=1, random_state=None).reset_index(drop=True)

    return df, list(known_abuse_request_ids), list(known_anomaly_request_ids)

def generate_normal_record(request_id, idx, base_serial_number):
    # Decide if this record is for a user or a machine
    is_machine_cert = random.random() < 0.3  # 30% chance it's a machine certificate

    # Random selection for RequesterName
    if is_machine_cert:
        # Machine certificate
        department = random.choice(departments)
        machine_name = generate_machine_name(department)
        requester_name = f"{DOMAIN_NAME}\\{machine_name}$"
        certificate_issued_cn = f"{machine_name}.{INTERNAL_DOMAIN}"
        certificate_subject = f"CN={machine_name}.{INTERNAL_DOMAIN}"

        # CertificateSANs
        san_types = ['DNS', 'IP']
        sans = []
        for _ in range(random.randint(1, 3)):
            san_type = random.choice(san_types)
            if san_type == 'DNS':
                sans.append(f"DNS:{machine_name}.{INTERNAL_DOMAIN}")
            elif san_type == 'IP':
                sans.append(f"IP:{fake.ipv4_private()}")
        certificate_sans = ", ".join(sans)

    else:
        # User certificate
        first_name = fake.first_name()
        last_name = fake.last_name()
        username = generate_username(first_name, last_name)
        requester_name = f"{DOMAIN_NAME}\\{username}"
        certificate_issued_cn = f"{first_name} {last_name}"
        certificate_subject = f"CN={first_name} {last_name}, OU={random.choice(departments)}, DC={INTERNAL_DOMAIN}"

        # CertificateSANs
        san_types = ['UPN', 'RFC822', 'URI']
        sans = []
        for _ in range(random.randint(1, 3)):
            san_type = random.choice(san_types)
            if san_type == 'UPN':
                sans.append(f"UPN:{username}@{DOMAIN_NAME}")
            elif san_type == 'RFC822':
                sans.append(f"RFC822:{username}@{DOMAIN_NAME}")
            elif san_type == 'URI':
                sans.append(f"URI:https://{DOMAIN_NAME}/users/{username}")
        certificate_sans = ", ".join(sans)

    # CertificateTemplate
    certificate_template = random.choice(list(certificate_templates.keys()))

    # EnhancedKeyUsage
    enhanced_key_usage = ", ".join(certificate_templates[certificate_template])

    # CertificateValidity
    validity_start = fake.date_time_this_decade(before_now=True, after_now=False)
    validity_end = validity_start + timedelta(days=random.randint(365, 365 * 5))

    # RequestSubmissionTime
    request_submission_time = validity_start

    # RequestDisposition
    request_disposition = "Issued"  # Always set to "Issued"

    # SerialNumber
    serial_number = base_serial_number + idx

    record = {
        "RequestID": request_id,
        "RequesterName": requester_name,
        "CertificateTemplate": certificate_template,
        "CertificateIssuedCommonName": certificate_issued_cn,
        "CertificateSubject": certificate_subject,
        "CertificateSANs": certificate_sans,
        "EnhancedKeyUsage": enhanced_key_usage,
        "CertificateValidityStart": validity_start.strftime('%Y-%m-%d %H:%M:%S'),
        "CertificateValidityEnd": validity_end.strftime('%Y-%m-%d %H:%M:%S'),
        "SerialNumber": serial_number,
        "RequestSubmissionTime": request_submission_time.strftime('%Y-%m-%d %H:%M:%S'),
        "RequestDisposition": request_disposition,
        "EKU": enhanced_key_usage,  # Added EKU field
    }

    return record

def generate_abuse_cases(num_abuses, used_request_ids, id_range_start, id_range_end):
    abuses = []
    abuse_ids = set()

    for _ in tqdm(range(num_abuses), desc="Generating Abuse Cases"):
        while True:
            request_id = random.randint(id_range_start, id_range_end)
            if request_id not in used_request_ids:
                used_request_ids.add(request_id)
                abuse_ids.add(request_id)
                break

        first_name = fake.first_name()
        last_name = fake.last_name()
        username = generate_username(first_name, last_name)
        requester_name = f"{DOMAIN_NAME}\\{username}"

        certificate_subject = f"CN={first_name} {last_name}, OU={random.choice(departments)}, DC={INTERNAL_DOMAIN}"
        certificate_sans = f"UPN:{username}@{DOMAIN_NAME}, DNS:{first_name.lower()}.{DOMAIN_NAME}"
        certificate_issued_cn = f"{first_name} {last_name}"

        abuse_field = random.choice(['subject', 'sans', 'common_name'])
        privileged_keyword = random.choice(privileged_keywords)

        if abuse_field == 'subject':
            certificate_subject = f"CN={privileged_keyword}, OU={random.choice(departments)}, DC={INTERNAL_DOMAIN}"
        elif abuse_field == 'sans':
            certificate_sans = f"UPN:{privileged_keyword.lower()}@{DOMAIN_NAME}"
        else:
            certificate_issued_cn = privileged_keyword

        certificate_template = random.choice(vulnerable_templates)
        enhanced_key_usage = "Client Authentication, Smart Card Logon"

        validity_start = fake.date_time_this_decade(before_now=True, after_now=False)
        validity_end = validity_start + timedelta(days=random.randint(365, 365 * 5))
        request_submission_time = validity_start
        request_disposition = "Issued"
        serial_number = random.randint(1000000, 9999999)

        record = {
            "RequestID": request_id,
            "RequesterName": requester_name,
            "CertificateTemplate": certificate_template,
            "CertificateIssuedCommonName": certificate_issued_cn,
            "CertificateSubject": certificate_subject,
            "CertificateSANs": certificate_sans,
            "EnhancedKeyUsage": enhanced_key_usage,
            "CertificateValidityStart": validity_start.strftime('%Y-%m-%d %H:%M:%S'),
            "CertificateValidityEnd": validity_end.strftime('%Y-%m-%d %H:%M:%S'),
            "SerialNumber": serial_number,
            "RequestSubmissionTime": request_submission_time.strftime('%Y-%m-%d %H:%M:%S'),
            "RequestDisposition": request_disposition,
            "Abuse_Flag": 1
        }

        abuses.append(record)

    return abuses, abuse_ids

def generate_anomaly_cases(num_anomalies, used_request_ids, id_range_start, id_range_end):
    anomalies = []
    anomaly_ids = set()

    for _ in tqdm(range(num_anomalies), desc="Generating Anomaly Cases"):
        while True:
            request_id = random.randint(id_range_start, id_range_end)
            if request_id not in used_request_ids:
                used_request_ids.add(request_id)
                anomaly_ids.add(request_id)
                break

        first_name = fake.first_name()
        last_name = fake.last_name()
        username = generate_username(first_name, last_name)
        requester_name = f"{DOMAIN_NAME}\\{username}"

        anomaly_type = random.choice(['unusual_template', 'high_volume', 'invalid_fields', 'unauthorized_eku', 'long_validity', 'off_hours'])

        certificate_template = random.choice(list(certificate_templates.keys()))
        certificate_issued_cn = f"{first_name} {last_name}"
        certificate_subject = f"CN={certificate_issued_cn}, OU={random.choice(departments)}, DC={INTERNAL_DOMAIN}"
        certificate_sans = f"UPN:{username}@{DOMAIN_NAME}"
        enhanced_key_usage = ", ".join(certificate_templates.get(certificate_template, []))

        if anomaly_type == 'unusual_template':
            certificate_template = "UnknownTemplate"
        elif anomaly_type == 'high_volume':
            pass  # Handled during feature engineering
        elif anomaly_type == 'invalid_fields':
            certificate_subject = "CN=???@@@###, OU=???@@@###, DC=Unknown"
            certificate_sans = "UPN:invalid@@domain"
        elif anomaly_type == 'unauthorized_eku':
            enhanced_key_usage = ", ".join(random.sample(abuse_ekus, k=random.randint(1, len(abuse_ekus))))
        elif anomaly_type == 'long_validity':
            validity_start = fake.date_time_this_decade(before_now=True, after_now=False)
            validity_end = validity_start + timedelta(days=random.randint(1825, 3650))
        elif anomaly_type == 'off_hours':
            request_submission_time = fake.date_time_this_decade(before_now=True, after_now=False)
            request_submission_time = request_submission_time.replace(hour=random.choice(range(0, 6)))
        else:
            validity_start = fake.date_time_this_decade(before_now=True, after_now=False)
            validity_end = validity_start + timedelta(days=random.randint(1095, 1825))

        if 'validity_start' not in locals():
            validity_start = fake.date_time_this_decade(before_now=True, after_now=False)
        if 'validity_end' not in locals():
            validity_end = validity_start + timedelta(days=random.randint(365, 365 * 5))
        if 'request_submission_time' not in locals():
            request_submission_time = validity_start

        request_disposition = "Issued"
        serial_number = random.randint(1000000, 9999999)

        record = {
            "RequestID": request_id,
            "RequesterName": requester_name,
            "CertificateTemplate": certificate_template,
            "CertificateIssuedCommonName": certificate_issued_cn,
            "CertificateSubject": certificate_subject,
            "CertificateSANs": certificate_sans,
            "EnhancedKeyUsage": enhanced_key_usage,
            "CertificateValidityStart": validity_start.strftime('%Y-%m-%d %H:%M:%S'),
            "CertificateValidityEnd": validity_end.strftime('%Y-%m-%d %H:%M:%S'),
            "SerialNumber": serial_number,
            "RequestSubmissionTime": request_submission_time.strftime('%Y-%m-%d %H:%M:%S'),
            "RequestDisposition": request_disposition,
            "Abuse_Flag": 1
        }

        anomalies.append(record)

    return anomalies, anomaly_ids

def update_config(training_abuse_ids, privileged_keywords, vulnerable_templates):
    config_path = "config.yaml"
    yaml = YAML()
    yaml.preserve_quotes = True

    with open(config_path, 'r') as file:
        config = yaml.load(file)

    config['known_abuse_request_ids'] = training_abuse_ids
    config['privileged_keywords'] = privileged_keywords
    config['vulnerable_templates'] = vulnerable_templates

    with open(config_path, 'w') as file:
        yaml.dump(config, file)

def main(args=None):

    # Initialize colorama
    init(autoreset=True)

    # === Configure Logging ===

    # Create logger
    logger = logging.getLogger('CertifEye-SyntheticDataGenerator')
    logger.setLevel(logging.DEBUG)

    # === Parse Command-Line Arguments ===
    parser = get_parser()
    if args is None:
        args = sys.argv[1:]
    try:
        args = parser.parse_args(args)
    except SystemExit:
        # Help message was displayed; return to console
        return


    if not logger.handlers:
        # Create handlers
        file_handler = logging.FileHandler('generate_synthetic_data.log')
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

    if args.verbose:
        console_handler.setLevel(logging.DEBUG)

    try:
        # === Generate Training Data ===

        logger.info(f"{Fore.WHITE}Generating training data with {args.train_records} records, {args.train_abuses} known abuses, and 10 anomalies...{Style.RESET_ALL}")
        try:
            training_data, training_abuse_ids, training_anomaly_ids = generate_synthetic_ca_logs(
                num_records=args.train_records,
                num_abuses=args.train_abuses,
                num_anomalies=args.anomalies,
                abuses_randomized=False,
                start_request_id=10000,
                label_anomalies=True  # Label anomalies as abuses in training data
            )

            # === Generate Detection Data ===

            logger.info(f"{Fore.WHITE}Generating detection data with {args.detect_records} records, {args.detect_abuses} known abuses, and 10 anomalies...{Style.RESET_ALL}")
            detection_data, detection_abuse_ids, detection_anomaly_ids = generate_synthetic_ca_logs(
                num_records=args.detect_records,
                num_abuses=args.detect_abuses,
                num_anomalies=args.anomalies,
                abuses_randomized=True,
                start_request_id=20000,
                label_anomalies=False  # Do not label anomalies in detection data
            )

            # === Output Summary ===

            # Output known abuse Request IDs for training data
            training_abuse_ids_sorted = sorted(training_abuse_ids)
            logger.info(f"{Fore.WHITE}\nKnown abuse Request IDs for training data: {Fore.CYAN}{training_abuse_ids_sorted}{Style.RESET_ALL}")

            # Output known anomaly Request IDs for training data
            training_anomaly_ids_sorted = sorted(training_anomaly_ids)
            logger.info(f"{Fore.WHITE}Anomaly Request IDs for training data: {Fore.YELLOW}{training_anomaly_ids_sorted}{Style.RESET_ALL}")

            # Output known abuse Request IDs for detection data
            detection_abuse_ids_sorted = sorted(detection_abuse_ids)
            logger.info(f"{Fore.WHITE}Known abuse Request IDs for detection data: {Fore.CYAN}{detection_abuse_ids_sorted}{Style.RESET_ALL}")

            # Output anomaly Request IDs for detection data
            detection_anomaly_ids_sorted = sorted(detection_anomaly_ids)
            logger.info(f"{Fore.WHITE}Anomaly Request IDs for detection data: {Fore.YELLOW}{detection_anomaly_ids_sorted}{Style.RESET_ALL}")

            # Output privileged keywords used
            logger.info(f"{Fore.WHITE}Privileged keywords used: {Fore.LIGHTBLACK_EX}{privileged_keywords}{Style.RESET_ALL}")

            # Output vulnerable templates used
            logger.info(f"{Fore.WHITE}Vulnerable templates used: {Fore.LIGHTBLACK_EX}{vulnerable_templates}{Style.RESET_ALL}")

            # === Save Data ===

            training_data.to_csv("synthetic_ca_logs_training.csv", index=False)
            logger.info(f"{Fore.GREEN}\nTraining data saved to {Fore.LIGHTBLACK_EX}'synthetic_ca_logs_training.csv'{Style.RESET_ALL}")

            detection_data.to_csv("synthetic_ca_logs_detection.csv", index=False)
            logger.info(f"{Fore.GREEN}Detection data saved to: {Fore.LIGHTBLACK_EX}'synthetic_ca_logs_detection.csv'{Style.RESET_ALL}")

            # === Update Config ===
            if args.update_config:
                update_config(training_abuse_ids_sorted, privileged_keywords, vulnerable_templates)
                logger.info(f"{Fore.GREEN}Config file updated with generated data.{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"{Fore.RED}\nOperation cancelled by user. Returning to console.{Style.RESET_ALL}")
            return
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=args.verbose)
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main()
