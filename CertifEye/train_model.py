# train_model.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Model Training Script
Author: glides
Version: 1.0

This script trains a machine learning model to detect potential abuses of Active Directory Certificate Services.
"""

import sys
import logging
import argparse
import yaml
import joblib
import pickle
import pandas as pd
import numpy as np
import re
from datetime import datetime
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE, RandomOverSampler
from colorama import init, Fore, Style
from certifeye_utils import flag_privileged_entries, print_banner

# Initialize colorama
init(autoreset=True)

# === Configure Logging ===

# Create logger
logger = logging.getLogger('CertifEye-TrainModel')
logger.setLevel(logging.DEBUG)

# Create handlers
file_handler = logging.FileHandler('train_model.log')
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

parser = argparse.ArgumentParser(description='CertifEye - Model Training Script')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
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

        # Paths
        ca_logs_pruned_path = config['paths']['ca_logs_pruned_path']
        model_output_path = config['paths']['model_output_path']
        params_output_path = config['paths']['params_output_path']

        # Training Mode
        training_mode = config.get('training_mode', 'supervised')

        # Known Abuse and Known Good Request IDs
        known_abuse_request_ids = config.get('known_abuse_request_ids', [])
        known_good_request_ids = config.get('known_good_request_ids', [])

        # Ensure IDs are sets for faster lookup and handle overlaps
        known_abuse_request_ids_set = set(known_abuse_request_ids)
        known_good_request_ids_set = set(known_good_request_ids)

        # Remove any overlaps between known abuse and known good IDs
        overlap_ids = known_abuse_request_ids_set.intersection(known_good_request_ids_set)
        if overlap_ids:
            logger.warning(f"{Fore.YELLOW}Request IDs {overlap_ids} are present in both known abuse and known good lists.{Style.RESET_ALL}")
            known_good_request_ids_set -= overlap_ids  # Prioritize abuse IDs

        # Privileged Keywords
        privileged_keywords = config['privileged_keywords']
        pattern = re.compile('|'.join(privileged_keywords), re.IGNORECASE)

        # Vulnerable Templates
        vulnerable_templates = config['vulnerable_templates']

        # Templates Requiring Approval (Optional)
        templates_requiring_approval = config.get('templates_requiring_approval', [])

        # Authorized Client Auth Users (Optional)
        authorized_client_auth_users = config.get('authorized_client_auth_users', [])
        authorized_client_auth_users = [user.lower() for user in authorized_client_auth_users]

        # Custom Thresholds
        validity_threshold = config.get('validity_threshold')
        request_volume_threshold = config.get('request_volume_threshold')

        # Off-hours Definition
        off_hours_start = config.get('off_hours_start', 19)  # Default to 7 PM
        off_hours_end = config.get('off_hours_end', 7)       # Default to 7 AM

        # === Load the CA Logs ===

        df = pd.read_csv(ca_logs_pruned_path)
        df['RequestID'] = df['RequestID'].astype(int)

        if df.empty:
            logger.error(f"{Fore.RED}CA logs DataFrame is empty. No data to train the model.{Style.RESET_ALL}")
            sys.exit(1)

        logger.info(f"{Fore.CYAN}Loaded CA logs with {len(df)} records.{Style.RESET_ALL}")

        # === Feature Engineering ===

        # Replace missing values in critical fields with default values
        df.fillna({
            'RequesterName': '',
            'CertificateTemplate': '',
            'CertificateIssuedCommonName': '',
            'CertificateSubject': '',
            'CertificateValidityStart': '',
            'CertificateValidityEnd': '',
            'EnhancedKeyUsage': '',
            'CertificateSANs': ''
        }, inplace=True)

        # Convert date columns to datetime
        date_columns = ['CertificateValidityStart', 'CertificateValidityEnd', 'RequestSubmissionTime']
        for col in date_columns:
            try:
                df[col] = pd.to_datetime(df[col], errors='coerce')
            except Exception as e:
                logger.error(f"Error converting column {col} to datetime: {e}")
                df[col] = pd.NaT

        # Drop rows with invalid dates
        initial_record_count = len(df)
        df.dropna(subset=date_columns, inplace=True)
        after_drop_count = len(df)
        logger.info(f"Dropped {initial_record_count - after_drop_count} records due to invalid dates.")

        if df.empty:
            logger.error(f"{Fore.RED}All records were dropped due to invalid dates.{Style.RESET_ALL}")
            sys.exit(1)

        # === Privileged Account Flagging ===

        df['Privileged_IssuedCN'] = df['CertificateIssuedCommonName'].apply(
            flag_privileged_entries, args=(pattern,)
        )
        df['Privileged_CertificateSubject'] = df['CertificateSubject'].apply(
            flag_privileged_entries, args=(pattern,)
        )
        df['Privileged_CertificateSANs'] = df['CertificateSANs'].apply(
            flag_privileged_entries, args=(pattern,)
        )

        # === Time-Based Features ===

        df['RequestHour'] = df['RequestSubmissionTime'].dt.hour
        df['Is_Off_Hours'] = df['RequestHour'].apply(
            lambda x: 1 if x >= off_hours_start or x < off_hours_end else 0
        )
        df['RequestWindow'] = df['RequestSubmissionTime'].dt.floor('h')

        # === Validity Period Anomalies ===

        df['CertificateValidityDuration'] = (
            df['CertificateValidityEnd'] - df['CertificateValidityStart']
        ).dt.days

        if validity_threshold is None:
            validity_threshold = df['CertificateValidityDuration'].mean() + 3 * df['CertificateValidityDuration'].std()
            logger.info(f"Calculated validity duration threshold: {validity_threshold:.2f} days.")
        else:
            logger.info(f"Using custom validity duration threshold: {validity_threshold} days.")

        df['Unusual_Validity_Period'] = df['CertificateValidityDuration'].apply(
            lambda x: 1 if x > validity_threshold else 0
        )

        # === Template Vulnerability Flags ===

        df['Vulnerable_Template'] = df['CertificateTemplate'].apply(
            lambda x: 1 if x in vulnerable_templates else 0
        )

        # === Requester Behavior Analysis ===

        df['Requests_Per_Hour'] = df.groupby(['RequesterName', 'RequestWindow'])['RequestID'].transform('count')

        if request_volume_threshold is None:
            request_volume_threshold = df['Requests_Per_Hour'].mean() + 3 * df['Requests_Per_Hour'].std()
            logger.info(f"Calculated request volume threshold: {request_volume_threshold:.2f} requests per hour.")
        else:
            logger.info(f"Using custom request volume threshold: {request_volume_threshold} requests per hour.")

        df['High_Request_Volume'] = df['Requests_Per_Hour'].apply(
            lambda x: 1 if x > request_volume_threshold else 0
        )

        # === Disposition Status Encoding ===

        # Save disposition categories before encoding
        disposition_categories = df['RequestDisposition'].unique().tolist()

        # Perform one-hot encoding
        df = pd.get_dummies(df, columns=['RequestDisposition'], prefix='Disposition')

        # === Prepare Features ===

        feature_cols = [
            'Privileged_IssuedCN',
            'Privileged_CertificateSubject',
            'Privileged_CertificateSANs',
            'Is_Off_Hours',
            'High_Request_Volume',
            'Vulnerable_Template',
            'Unusual_Validity_Period',
        ] + [col for col in df.columns if col.startswith('Disposition_')]

        # Ensure all expected columns are present
        missing_cols = [col for col in feature_cols if col not in df.columns]
        if missing_cols:
            missing_df = pd.DataFrame(0, index=df.index, columns=missing_cols)
            df = pd.concat([df, missing_df], axis=1)

        X = df[feature_cols].copy()

        # Handle missing or infinite values
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        # === Training Mode Selection ===

        if training_mode in ['supervised', 'hybrid']:
            logger.info(f"{Fore.CYAN}Supervised learning mode activated.{Style.RESET_ALL}")

            # Add 'Abuse_Flag' column with default value 0
            df['Abuse_Flag'] = 0

            # Label known abuse instances as 1
            df.loc[df['RequestID'].isin(known_abuse_request_ids_set), 'Abuse_Flag'] = 1

            # Ensure known good instances are labeled as 0
            df.loc[df['RequestID'].isin(known_good_request_ids_set), 'Abuse_Flag'] = 0

            y = df['Abuse_Flag']

            # Check class distribution
            class_counts = y.value_counts()
            logger.info("Class distribution before oversampling:")
            logger.info(f"\n{class_counts}")

            # Handle imbalanced classes
            if class_counts.min() < 6:
                logger.warning(f"{Fore.YELLOW}Minority class has too few samples for SMOTE. Using RandomOverSampler instead.{Style.RESET_ALL}")
                ros = RandomOverSampler(random_state=42)
                X_resampled, y_resampled = ros.fit_resample(X, y)
                synthetic_samples = len(X_resampled) - len(X)
                logger.info(f"Oversampling added {synthetic_samples} samples to balance classes.")
            else:
                smote = SMOTE(random_state=42)
                X_resampled, y_resampled = smote.fit_resample(X, y)
                synthetic_samples = len(X_resampled) - len(X)
                logger.info(f"SMOTE generated {synthetic_samples} synthetic samples.")

            # Check class distribution after oversampling
            resampled_class_counts = pd.Series(y_resampled).value_counts()
            logger.info("Class distribution after oversampling:")
            logger.info(f"\n{resampled_class_counts}")

            # === Split Data ===

            X_train, X_test, y_train, y_test = train_test_split(
                X_resampled, y_resampled, test_size=0.2, random_state=42
            )
            logger.info(f"Training data size: {len(X_train)}, Test data size: {len(X_test)}")

            # === Create a Pipeline with Grid Search ===

            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', RandomForestClassifier(random_state=42))
            ])

            # Define parameter grid
            param_grid = {
                'classifier__n_estimators': [100, 200],
                'classifier__max_depth': [None, 10, 20],
                'classifier__min_samples_leaf': [1, 2, 5],
                'classifier__class_weight': ['balanced']
            }

            # Create GridSearchCV
            grid_search = GridSearchCV(
                estimator=pipeline,
                param_grid=param_grid,
                cv=5,
                scoring='roc_auc',
                n_jobs=-1
            )

            # Fit grid search
            grid_search.fit(X_train, y_train)
            logger.info(f"{Fore.GREEN}Best parameters found: {grid_search.best_params_}{Style.RESET_ALL}")

            # Best estimator
            pipeline = grid_search.best_estimator_

            # === Evaluate the Model ===

            y_pred = pipeline.predict(X_test)
            y_pred_proba = pipeline.predict_proba(X_test)[:, 1]

            logger.info("Classification Report:")
            report = classification_report(y_test, y_pred)
            logger.info(f"\n{report}")

            logger.info("Confusion Matrix:")
            cm = confusion_matrix(y_test, y_pred)
            logger.info(f"\n{cm}")

            roc_auc = roc_auc_score(y_test, y_pred_proba)
            logger.info(f"ROC AUC Score: {roc_auc:.2f}")

            # Precision-Recall Curve AUC
            precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
            pr_auc = auc(recall, precision)
            logger.info(f"Precision-Recall AUC Score: {pr_auc:.2f}")

            # Cross-Validation Scores
            cv_scores = cross_val_score(pipeline, X_resampled, y_resampled, cv=5, scoring='roc_auc')
            logger.info(f"Cross-validated ROC AUC scores: {cv_scores}")
            logger.info(f"Mean ROC AUC: {np.mean(cv_scores):.2f}")

            # === Feature Importance Analysis ===

            importances = pipeline.named_steps['classifier'].feature_importances_
            feature_names = X.columns

            feature_importance_df = pd.DataFrame({
                'Feature': feature_names,
                'Importance': importances
            }).sort_values(by='Importance', ascending=False)

            logger.info("Feature Importances:")
            logger.info(f"\n{feature_importance_df}")

        else:
            logger.info(f"{Fore.CYAN}Unsupervised learning mode activated.{Style.RESET_ALL}")
            # === Unsupervised Learning Using Isolation Forest ===

            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('isolation_forest', IsolationForest(n_estimators=200, contamination=0.01, random_state=42))
            ])

            pipeline.fit(X)
            logger.info("Isolation Forest model training completed.")

        # === Save the Trained Model and Parameters ===

        joblib.dump(pipeline, model_output_path)
        logger.info(f"{Fore.GREEN}Model saved to {model_output_path}{Style.RESET_ALL}")

        with open(params_output_path, 'wb') as f:
            pickle.dump({
                'feature_cols': feature_cols,
                'pattern': pattern,
                'vulnerable_templates': vulnerable_templates,
                'validity_threshold': validity_threshold,
                'templates_requiring_approval': templates_requiring_approval,
                'authorized_client_auth_users': authorized_client_auth_users,
                'training_mode': training_mode,
                'disposition_categories': disposition_categories  # Use the variable saved before encoding
            }, f)
        logger.info(f"{Fore.GREEN}Parameters saved to {params_output_path}{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\nOperation cancelled by user. Exiting gracefully.{Style.RESET_ALL}")
        sys.exit(0)
    except FileNotFoundError as fnf_error:
        logger.error(f"{Fore.RED}File not found: {fnf_error}{Style.RESET_ALL}", exc_info=True)
    except ValueError as val_error:
        logger.error(f"{Fore.RED}Value error: {val_error}{Style.RESET_ALL}", exc_info=True)
    except Exception as e:
        logger.error(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}", exc_info=True)
