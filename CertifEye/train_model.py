#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CertifEye - Model Training Script
Author: glides
Version: 0.9.2

This script trains a machine learning model to detect potential abuses
of Active Directory Certificate Services, including both known abuses
and anomalies.
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
from sklearn.model_selection import (
    train_test_split,
    GridSearchCV,
    StratifiedKFold,
    cross_val_score,
)
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE, RandomOverSampler
from colorama import init, Fore, Style
from certifeye_utils import (
    get_logger,
    load_config,
    engineer_features,  # Import the shared function
)

# === Configure Logging ===

# Initialize colorama
init(autoreset=True)

# Create logger
logger = get_logger('CertifEye-TrainModel')


def get_parser():
    """
    Get the argument parser for the script.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='CertifEye - Model Training Script')
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='Increase verbosity level (e.g., -v, -vv)',
    )
    return parser


def main(args=None):
    """
    Main function to execute the model training process.
    """
    global logger

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
        ca_logs_pruned_path = config['paths']['ca_logs_pruned_path']
        model_output_path = config['paths']['model_output_path']
        params_output_path = config['paths']['params_output_path']

        # Algorithm Selection: 'random_forest' or 'xgboost'
        algorithm = config.get('algorithm', 'random_forest')

        # Training Mode
        training_mode = config.get('training_mode', 'supervised')

        # Known Abuse and Known Good Request IDs
        known_abuse_request_ids = config.get('known_abuse_request_ids', [])
        known_good_request_ids = config.get('known_good_request_ids', [])

        # Known Anomaly Request IDs (new)
        known_anomaly_request_ids = config.get('known_anomaly_request_ids', [])

        # Ensure IDs are sets and handle overlaps
        known_abuse_request_ids_set = set(known_abuse_request_ids)
        known_anomaly_request_ids_set = set(known_anomaly_request_ids)
        known_good_request_ids_set = set(known_good_request_ids)

        # Remove overlaps between known abuse, anomalies, and known good IDs
        overlap_ids = known_abuse_request_ids_set.intersection(known_good_request_ids_set)
        if overlap_ids:
            logger.warning(
                f"{Fore.YELLOW}Request IDs {overlap_ids} present in both known abuse and known good lists. "
                f"Prioritizing as abuse.{Style.RESET_ALL}"
            )
            known_good_request_ids_set -= overlap_ids  # Prioritize abuse IDs

        overlap_anomaly_ids = known_anomaly_request_ids_set.intersection(known_good_request_ids_set)
        if overlap_anomaly_ids:
            logger.warning(
                f"{Fore.YELLOW}Request IDs {overlap_anomaly_ids} present in both anomalies and known good lists. "
                f"Prioritizing as anomalies.{Style.RESET_ALL}"
            )
            known_good_request_ids_set -= overlap_anomaly_ids

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
        validity_threshold = config.get('validity_threshold', 730)  # Default to 730 days if not set

        # Off-hours Definition
        off_hours_start = config.get('off_hours_start', 19)  # Default to 7 PM
        off_hours_end = config.get('off_hours_end', 7)       # Default to 7 AM

        # === Load the CA Logs ===
        logger.info(f"Loading pruned CA logs from: {ca_logs_pruned_path}")
        df = pd.read_csv(ca_logs_pruned_path)
        df['RequestID'] = df['RequestID'].astype(int)

        if df.empty:
            logger.error(
                f"{Fore.RED}CA logs DataFrame is empty. No data to train the model.{Style.RESET_ALL}"
            )
            return

        logger.info(
            f"{Fore.WHITE}Loaded CA logs with {len(df)} records.{Style.RESET_ALL}"
        )

        # === Feature Engineering ===

        # Replace missing values in critical fields with default values
        df.fillna(
            {
                'RequesterName': '',
                'CertificateTemplate': '',
                'CertificateIssuedCommonName': '',
                'CertificateSubject': '',
                'CertificateValidityStart': '',
                'CertificateValidityEnd': '',
                'EnhancedKeyUsage': '',
                'CertificateSANs': '',
                'RequestDisposition': ''
            },
            inplace=True
        )

        # Handle multi-line 'CertificateSANs'
        df['CertificateSANs'] = (
            df['CertificateSANs']
            .astype(str)
            .str.replace('\n', ' ')
            .str.replace('\r', ' ')
        )

        # Convert date columns to datetime
        date_columns = [
            'CertificateValidityStart',
            'CertificateValidityEnd',
            'RequestSubmissionTime'
        ]
        df[date_columns] = df[date_columns].apply(pd.to_datetime, errors='coerce')

        # Drop rows with invalid dates
        initial_record_count = len(df)
        df.dropna(subset=date_columns, inplace=True)
        after_drop_count = len(df)
        dropped_records = initial_record_count - after_drop_count
        if dropped_records > 0:
            logger.debug(
                f"Dropped {dropped_records} records due to invalid dates."
            )

        if df.empty:
            logger.error(
                f"{Fore.RED}All records were dropped due to invalid dates.{Style.RESET_ALL}"
            )
            return

        # === Prepare Features ===

        # Define feature columns
        feature_cols = [
            'Privileged_IssuedCN',
            'Privileged_CertificateSubject',
            'Privileged_CertificateSANs',
            'Privileged_and_Vulnerable',
            'Is_Off_Hours',
            'High_Request_Volume',
            'Requests_Last_24h',
            'Vulnerable_Template',
            'Unusual_Validity_Period',
            'Disposition_Issued'
            # Add new features here if implemented in certifeye_utils.py
            # Example: 'Requests_Per_Hour'
        ]

        # Engineer features using the shared function
        X = engineer_features(
            df,
            feature_cols,
            validity_threshold,
            pattern,
            vulnerable_templates,
            templates_requiring_approval,
            authorized_client_auth_users,
            training_mode,
            detection_mode=False  # Indicate we're in training mode
        )

        # Handle missing or infinite values
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        # === Training Mode Selection ===
        if training_mode in ['supervised', 'hybrid']:
            logger.info(f"{Fore.WHITE}Supervised learning mode activated.{Style.RESET_ALL}")

            # Use 'Abuse_Flag' if it exists in the DataFrame, else initialize
            if 'Abuse_Flag' not in df.columns:
                df['Abuse_Flag'] = 0

            # Label known abuse instances as 1
            df.loc[df['RequestID'].isin(known_abuse_request_ids_set), 'Abuse_Flag'] = 1

            # Label anomalies as 1
            df.loc[df['RequestID'].isin(known_anomaly_request_ids_set), 'Abuse_Flag'] = 1

            # Ensure known good instances are labeled as 0
            df.loc[df['RequestID'].isin(known_good_request_ids_set), 'Abuse_Flag'] = 0

            y = df['Abuse_Flag']

            # Log class distribution
            class_counts = y.value_counts().to_dict()
            logger.info(f"Class distribution before oversampling: {class_counts}")

            # Handle imbalanced classes
            if y.value_counts().min() < 6:
                logger.warning(
                    f"{Fore.YELLOW}Minority class has too few samples for SMOTE. "
                    f"Using RandomOverSampler instead.{Style.RESET_ALL}"
                )
                sampler = RandomOverSampler(random_state=42)
                sampling_strategy = 'RandomOverSampler'
            else:
                sampler = SMOTE(random_state=42)
                sampling_strategy = 'SMOTE'

            X_resampled, y_resampled = sampler.fit_resample(X, y)

            synthetic_samples = len(X_resampled) - len(X)
            logger.info(
                f"{Fore.CYAN}{sampling_strategy} added {synthetic_samples} samples to balance classes.{Style.RESET_ALL}"
            )

            logger.debug(f"Class distribution after oversampling:\n{pd.Series(y_resampled).value_counts()}")

            # === Split Data ===
            X_train, X_test, y_train, y_test = train_test_split(
                X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled
            )
            logger.debug(
                f"Training data size: {len(X_train)}, Test data size: {len(X_test)}"
            )

            # === Choose Classifier ===
            if algorithm == 'xgboost':
                classifier = XGBClassifier(
                    eval_metric='logloss',
                    random_state=42
                )
                param_grid = {
                    'classifier__n_estimators': [100, 200],
                    'classifier__max_depth': [3, 6],
                    'classifier__learning_rate': [0.01, 0.1],
                    'classifier__subsample': [0.7, 1.0],
                    'classifier__colsample_bytree': [0.7, 1.0],
                }
            else:  # Default to Random Forest
                classifier = RandomForestClassifier(
                    random_state=42,
                    class_weight='balanced'
                )
                param_grid = {
                    'classifier__n_estimators': [100, 200],
                    'classifier__max_depth': [None, 10, 20],
                    'classifier__min_samples_leaf': [1, 2],
                    'classifier__max_features': [None, 'sqrt', 'log2'],
                }

            # === Create a Pipeline ===
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', classifier)
            ])

            cv_strategy = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

            grid_search = GridSearchCV(
                estimator=pipeline,
                param_grid=param_grid,
                cv=cv_strategy,
                scoring='roc_auc',
                n_jobs=-1,
                error_score='raise',
                verbose=1  # Adjusted verbosity
            )

            # Fit grid search
            logger.info("Starting Grid Search Cross-Validation...")
            grid_search.fit(X_train, y_train)

            logger.info(
                f"{Fore.GREEN}Best parameters found: {grid_search.best_params_}{Style.RESET_ALL}"
            )

            # Best estimator
            pipeline = grid_search.best_estimator_

            # === Evaluate the Model ===
            y_pred = pipeline.predict(X_test)
            y_pred_proba = pipeline.predict_proba(X_test)[:, 1]

            # Classification Metrics
            roc_auc = roc_auc_score(y_test, y_pred_proba)
            precision, recall, thresholds = precision_recall_curve(y_test, y_pred_proba)
            pr_auc = auc(recall, precision)
            cv_scores = cross_val_score(
                pipeline, X_resampled, y_resampled, cv=cv_strategy, scoring='roc_auc'
            )
            mean_cv_score = np.mean(cv_scores)

            # Additional Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision_score_value = precision_score(y_test, y_pred)
            recall_score_value = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            conf_matrix = confusion_matrix(y_test, y_pred)

            if args.verbose >= 1:
                logger.info(f"{Fore.WHITE}ROC AUC Score: {Fore.LIGHTBLACK_EX}{roc_auc:.2f}{Style.RESET_ALL}")
                logger.info(
                    f"{Fore.WHITE}Precision-Recall AUC Score: {Fore.LIGHTBLACK_EX}{pr_auc:.2f}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}Cross-validated ROC AUC scores: {Fore.LIGHTBLACK_EX}{cv_scores}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}Mean ROC AUC: {Fore.LIGHTBLACK_EX}{mean_cv_score:.2f}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}Accuracy: {Fore.LIGHTBLACK_EX}{accuracy:.2f}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}Precision: {Fore.LIGHTBLACK_EX}{precision_score_value:.2f}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}Recall: {Fore.LIGHTBLACK_EX}{recall_score_value:.2f}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}F1 Score: {Fore.LIGHTBLACK_EX}{f1:.2f}{Style.RESET_ALL}"
                )
                logger.info(
                    f"{Fore.WHITE}Confusion Matrix:\n{Fore.LIGHTBLACK_EX}{conf_matrix}{Style.RESET_ALL}"
                )

            # === Assign feature_names and classifier regardless of verbosity ===
            feature_names = X.columns
            classifier = pipeline.named_steps['classifier']

            if hasattr(classifier, 'feature_importances_'):
                importances = classifier.feature_importances_
                feature_importance_df = pd.DataFrame({
                    'Feature': feature_names,
                    'Importance': importances
                })
                feature_importance_df = feature_importance_df.sort_values(
                    by='Importance', ascending=False
                ).reset_index(drop=True)
            else:
                importances = None
                feature_importance_df = None

            if args.verbose >= 2:
                logger.info(f"{Fore.WHITE}\nClassification Report:\n{Style.RESET_ALL}")
                logger.info(classification_report(y_test, y_pred))

                if importances is not None:
                    logger.debug(
                        f"{Fore.YELLOW}\nFeature Importances:\n{Style.RESET_ALL}"
                    )
                    logger.debug(f"{Fore.LIGHTYELLOW_EX}{feature_importance_df}\n{Style.RESET_ALL}")
                else:
                    logger.warning("Classifier does not support feature importances.")

            # === Ensuring Critical Features are Weighted Properly ===
            # Critical features should have significant importance
            important_features = [
                'Privileged_and_Vulnerable',
                'Vulnerable_Template',
                'Privileged_CertificateSANs',
                'Privileged_CertificateSubject',
                'Privileged_IssuedCN'
                # Add new critical features if necessary
            ]
            low_importance_features = []
            for feature in important_features:
                if feature not in feature_names:
                    logger.warning(f"Feature {feature} not found in feature names.")
                else:
                    if importances is not None:
                        importance = feature_importance_df.loc[
                            feature_importance_df['Feature'] == feature,
                            'Importance'
                        ].values[0]
                        if importance < 0.01:
                            low_importance_features.append(feature)
                        logger.debug(f"Feature {feature} importance: {importance}")
                    else:
                        logger.warning(f"Cannot determine importance for feature {feature} as the classifier does not provide feature importances.")

            if low_importance_features:
                logger.warning(f"The following critical features have low importance: {low_importance_features}")

            # Optionally, re-train the model with adjusted parameters if necessary

        else:
            logger.info(f"{Fore.CYAN}Unsupervised learning mode activated.{Style.RESET_ALL}")
            # === Unsupervised Learning Using Isolation Forest ===
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('isolation_forest', IsolationForest(
                    n_estimators=200, contamination=0.01, random_state=42)
                )
            ])

            pipeline.fit(X)
            logger.info("Isolation Forest model training completed.")

        # === Save the Trained Model and Parameters ===
        joblib.dump(pipeline, model_output_path)
        logger.info(
            f"{Fore.GREEN}Model saved to: {Fore.LIGHTBLACK_EX}{model_output_path}{Style.RESET_ALL}"
        )

        with open(params_output_path, 'wb') as f:
            pickle.dump({
                'feature_cols': feature_cols,
                'pattern': pattern,
                'vulnerable_templates': vulnerable_templates,
                'validity_threshold': validity_threshold,
                'templates_requiring_approval': templates_requiring_approval,
                'authorized_client_auth_users': authorized_client_auth_users,
                'training_mode': training_mode,
                'algorithm': algorithm
                # Add any new parameters if necessary
            }, f)
        logger.info(
            f"{Fore.GREEN}Parameters saved to: {Fore.LIGHTBLACK_EX}{params_output_path}{Style.RESET_ALL}"
        )

    except KeyboardInterrupt:
        print(
            f"{Fore.RED}\nOperation cancelled by user. Returning to console.{Style.RESET_ALL}"
        )
        return
    except FileNotFoundError as fnf_error:
        logger.error(
            f"{Fore.RED}File not found: {fnf_error}{Style.RESET_ALL}", exc_info=args.verbose >= 1
        )
    except ValueError as val_error:
        logger.error(
            f"{Fore.RED}Value error: {val_error}{Style.RESET_ALL}", exc_info=args.verbose >= 1
        )
    except Exception as e:
        logger.error(
            f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}", exc_info=args.verbose >= 1
        )

if __name__ == '__main__':
    main()
