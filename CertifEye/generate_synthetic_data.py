#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Synthetic CA Log Data Generator
Author: glides
Version: 0.9.1

This script generates synthetic CA log data similar in structure to the original data,
without including any sensitive information. It generates training and detection datasets
with configurable numbers of known abuses.
"""

import random
import pandas as pd
import numpy as np
import argparse
import logging
import sys
import yaml
from datetime import datetime, timedelta
from faker import Faker
from colorama import init, Fore, Style

# === Configuration ===

DOMAIN_NAME = "contoso.com"  # Use a consistent domain name

# Certificate Templates (Add more if needed)
certificate_templates = [
    "UserCertificate",
    "MachineCertificate",
    "AdminCertificate",
    "ServerCertificate",
    "EncryptionCertificate",
    "VPNCertificate",
    "EmailCertificate",
    "SMIMECertificate",
    "CodeSigningCertificate",
    "DomainControllerCertificate"
]

# Vulnerable Templates (Abuse Cases)
vulnerable_templates = [
    "AdminCertificate",
    "DomainControllerCertificate",
    "CodeSigningCertificate"
]

# Enhanced Key Usages (Add more if needed)
enhanced_key_usages = [
    "Client Authentication",
    "Server Authentication",
    "Code Signing",
    "Secure Email",
    "Time Stamping",
    "OCSP Signing",
    "Document Signing",
    "Any Purpose"
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

# Initialize Faker
fake = Faker()

def get_parser():
    parser = argparse.ArgumentParser(description='CertifEye - Synthetic Data Generator')
    parser.add_argument('-tr', '--train_records', type=int, default=1000, help='Number of training records to generate')
    parser.add_argument('-ta', '--train_abuses', type=int, default=6, help='Number of known abuses for training')
    parser.add_argument('-dr', '--detect_records', type=int, default=5000, help='Number of detection records to generate')
    parser.add_argument('-da', '--detect_abuses', type=int, default=20, help='Number of abuses in detection data')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    # args = parser.parse_args()
    return parser

def main(args=None):
    parser = get_parser()
    if args is None:
        args = sys.argv[1:]
    args = parser.parse_args(args)

    # Initialize colorama
    init(autoreset=True)

    # === Configure Logging ===

    # Create logger
    logger = logging.getLogger('CertifEye-SyntheticDataGenerator')
    logger.setLevel(logging.DEBUG)

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

# === Parse Command-Line Arguments ===

    parser = argparse.ArgumentParser(description='CertifEye - Synthetic Data Generator')
    parser.add_argument('-tr', '--train_records', type=int, default=1000, help='Number of training records to generate')
    parser.add_argument('-ta', '--train_abuses', type=int, default=6, help='Number of known abuses for training')
    parser.add_argument('-dr', '--detect_records', type=int, default=5000, help='Number of detection records to generate')
    parser.add_argument('-da', '--detect_abuses', type=int, default=20, help='Number of abuses in detection data')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    if args.verbose:
        console_handler.setLevel(logging.DEBUG)

    try:
        # print_banner()

        # === Generate Training Data ===

        logger.info(f"{Fore.WHITE}Generating training data with {args.train_records} records and {args.train_abuses} known abuses...{Style.RESET_ALL}")
        # Place known abuses at the end of training data
        training_data, training_abuse_ids = generate_synthetic_ca_logs(
            num_records=args.train_records + args.train_abuses,
            num_abuses=args.train_abuses,
            abuses_randomized=False,
            start_request_id=10000
        )

        # === Generate Detection Data ===

        logger.info(f"{Fore.WHITE}Generating detection data with {args.detect_records} records and {args.detect_abuses} abuses...{Style.RESET_ALL}")
        # Randomize abuses in detection data
        detection_data, detection_abuse_ids = generate_synthetic_ca_logs(
            num_records=args.detect_records,
            num_abuses=args.detect_abuses,
            abuses_randomized=True,
            start_request_id=20000  # Ensure RequestIDs do not overlap with training data
        )

        # === Output Summary ===

        # Output known abuse Request IDs for training data
        training_abuse_ids_sorted = sorted(training_abuse_ids)
        logger.info(f"{Fore.WHITE}\nKnown abuse Request IDs for training data: {Fore.CYAN}{training_abuse_ids_sorted}{Style.RESET_ALL}")


        # Output known abuse Request IDs for detection data
        detection_abuse_ids_sorted = sorted(detection_abuse_ids)
        logger.info(f"{Fore.WHITE}Abuse Request IDs in detection data: {Fore.YELLOW}{detection_abuse_ids_sorted}{Style.RESET_ALL}{Style.RESET_ALL}")


        # Output privileged keywords used
        logger.info(f"{Fore.WHITE}Privileged keywords used: {Fore.LIGHTBLACK_EX}{privileged_keywords}{Style.RESET_ALL}")


        # Output vulnerable templates used
        logger.info(f"{Fore.WHITE}Vulnerable templates used: {Fore.LIGHTBLACK_EX}{vulnerable_templates}{Style.RESET_ALL}")


        # === Save Data ===
        
        training_data.to_csv("synthetic_ca_logs_training.csv", index=False)
        logger.info(f"{Fore.GREEN}\nTraining data saved to {Fore.LIGHTBLACK_EX}'synthetic_ca_logs_training.csv'{Style.RESET_ALL}")

        detection_data.to_csv("synthetic_ca_logs_detection.csv", index=False)
        logger.info(f"{Fore.GREEN}Detection data saved to: {Fore.LIGHTBLACK_EX}'synthetic_ca_logs_detection.csv'{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperation cancelled by user. Exiting gracefully.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

# === User and Machine Naming Conventions ===

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

# === Data Generation Functions ===

def generate_synthetic_ca_logs(num_records, num_abuses=0, abuses_randomized=True, start_request_id=10000):
    data = []
    known_abuse_request_ids = set()
    used_request_ids = set()

    base_request_id = start_request_id  # Starting RequestID
    base_serial_number = 1000000  # Starting SerialNumber

    total_records = num_records
    normal_records = total_records - num_abuses

    # Generate unique RequestIDs for normal records
    normal_request_ids = random.sample(range(base_request_id, base_request_id + total_records * 2), normal_records)
    used_request_ids.update(normal_request_ids)

    # Generate normal records
    for idx, request_id in enumerate(normal_request_ids):
        # Decide if this record is for a user or a machine
        is_machine_cert = random.random() < 0.3  # 30% chance it's a machine certificate

        # Random selection for RequesterName
        if is_machine_cert:
            # Machine certificate
            department = random.choice(departments)
            machine_name = generate_machine_name(department)
            requester_name = f"{DOMAIN_NAME}\\{machine_name}$"
            certificate_issued_cn = f"{machine_name}.{DOMAIN_NAME}"
            certificate_subject = f"CN={machine_name}.{DOMAIN_NAME}"

            # CertificateSANs
            san_types = ['DNS', 'IP']
            sans = []
            for _ in range(random.randint(1, 3)):
                san_type = random.choice(san_types)
                if san_type == 'DNS':
                    sans.append(f"DNS:{machine_name}.{DOMAIN_NAME}")
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
            certificate_subject = f"CN={first_name} {last_name}, OU={random.choice(departments)}, DC={DOMAIN_NAME}"

            # CertificateSANs
            san_types = ['email', 'UPN', 'URI']
            sans = []
            for _ in range(random.randint(1, 3)):
                san_type = random.choice(san_types)
                if san_type == 'email':
                    sans.append(f"RFC822:{username}@{DOMAIN_NAME}")
                elif san_type == 'UPN':
                    sans.append(f"UPN:{username}@{DOMAIN_NAME}")
                elif san_type == 'URI':
                    sans.append(f"URI:https://{DOMAIN_NAME}/users/{username}")
            certificate_sans = ", ".join(sans)

        # CertificateTemplate
        certificate_template = random.choice(certificate_templates)

        # EnhancedKeyUsage
        eku_list = random.sample(enhanced_key_usages, k=random.randint(1, 3))
        enhanced_key_usage = ", ".join(eku_list)

        # Validity Period
        validity_start = fake.date_time_between(start_date='-1y', end_date='now')
        validity_days = random.randint(365, 1095)  # Valid for 1 to 3 years
        validity_end = validity_start + timedelta(days=validity_days)

        # SerialNumber
        serial_number = base_serial_number + idx

        # RequestSubmissionTime
        request_submission_time = validity_start - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))

        # RequestDisposition
        request_disposition = random.choices(
            request_dispositions,
            weights=[0.85, 0.1, 0.03, 0.02],  # Heavier weight to 'Issued'
            k=1
        )[0]

        # Potentially include a privileged keyword in the RequesterName for admins
        if random.random() < 0.05:  # 5% chance
            privileged_keyword = random.choice(privileged_keywords)
            requester_name = f"{DOMAIN_NAME}\\{privileged_keyword}{random.randint(1,99)}"

        # Create the record
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
            "RequestDisposition": request_disposition
        }

        data.append(record)

    df = pd.DataFrame(data)

    # Generate abuse cases
    if num_abuses > 0:
        abuse_records, abuse_ids = generate_abuse_cases(
            num_abuses,
            used_request_ids,
            base_request_id,
            base_request_id + total_records * 2
        )
        known_abuse_request_ids.update(abuse_ids)
        abuse_df = pd.DataFrame(abuse_records)

        # Combine normal and abuse records
        df = pd.concat([df, abuse_df], ignore_index=True)

        if abuses_randomized:
            # Shuffle records
            df = df.sample(frac=1, random_state=None).reset_index(drop=True)

    return df, list(known_abuse_request_ids)

def generate_abuse_cases(num_abuses, used_request_ids, id_range_start, id_range_end):
    abuses = []
    abuse_ids = set()

    for _ in range(num_abuses):
        # Assign a random unique RequestID that isn't already used
        while True:
            request_id = random.randint(id_range_start, id_range_end)
            if request_id not in used_request_ids:
                used_request_ids.add(request_id)
                abuse_ids.add(request_id)
                break

        # Low-level requester
        first_name = fake.first_name()
        last_name = fake.last_name()
        username = generate_username(first_name, last_name)
        requester_name = f"{DOMAIN_NAME}\\{username}"

        # Deliberate abuse patterns with high-level accounts in Subject/SANs
        privileged_keyword = random.choice(privileged_keywords)

        # CertificateTemplate known to be vulnerable
        certificate_template = random.choice(vulnerable_templates)

        # CertificateIssuedCommonName and CertificateSubject
        certificate_issued_cn = f"{privileged_keyword}.{DOMAIN_NAME}"
        certificate_subject = f"CN={certificate_issued_cn}"

        # CertificateSANs containing privileged keyword
        san_types = ['DNS', 'IP']
        sans = []
        for _ in range(random.randint(1, 3)):
            san_type = random.choice(san_types)
            if san_type == 'DNS':
                sans.append(f"DNS:{privileged_keyword}.{DOMAIN_NAME}")
            elif san_type == 'IP':
                sans.append(f"IP:{fake.ipv4_private()}")
        certificate_sans = ", ".join(sans)

        # EnhancedKeyUsage including sensitive usages
        eku_list = ["Client Authentication", "Server Authentication"]
        enhanced_key_usage = ", ".join(eku_list)

        # Validity Period (unusually long)
        validity_start = fake.date_time_between(start_date='-1y', end_date='now')
        validity_days = random.randint(1825, 3650)  # 5 to 10 years
        validity_end = validity_start + timedelta(days=validity_days)

        # SerialNumber
        serial_number = request_id  # Or use a separate serial number sequence if needed

        # RequestSubmissionTime
        request_submission_time = validity_start - timedelta(days=random.randint(0, 5), hours=random.randint(0, 23))

        # RequestDisposition (usually 'Issued' for abuse cases)
        request_disposition = "Issued"

        # Create the abuse record
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
            "RequestDisposition": request_disposition
        }

        abuses.append(record)

    return abuses, abuse_ids

# === Main Execution ===

if __name__ == '__main__':
    main()        