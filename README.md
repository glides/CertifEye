# CertifEye

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

An AI-powered detection system for identifying potential abuse of Active Directory Certificate Services (AD CS) misconfigurations by analyzing Certificate Authority (CA) logs.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Configuration File (`config.yaml`)](#configuration-file-configyaml)
  - [Exporting CA Logs Using PowerShell](#exporting-ca-logs-using-powershell)
  - [Training the Model](#training-the-model)
  - [Detecting Abuse](#detecting-abuse)
- [Sample Data](#sample-data)
- [Implementation Examples](#implementation-examples)
  - [Integration with SIEM Platforms](#integration-with-siem-platforms)
  - [Automated Alerting](#automated-alerting)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

**CertifEye** is a powerful tool designed to detect and prevent the abuse of Active Directory Certificate Services (AD CS) misconfigurations, including multiple Enterprise Security Configuration (ESC) abuses. By leveraging machine learning algorithms and anomaly detection techniques, CertifEye analyzes CA logs to identify suspicious activities, potential exploits, and unauthorized privilege escalations. The system is flexible, scalable, and can be integrated into existing security infrastructures to enhance your organization's security posture.

---

## Project Structure

```
CertifEye/
├── certifeye.py             # Main script for detecting abuse
├── prune_data.py            # Script to assist pruning a large dataset for training the model
├── train_model.py           # Script for training the machine learning model
├── certifeye_utils.py       # Utility functions used across scripts
├── config.yaml              # Configuration file in YAML format
├── requirements.txt         # Python package dependencies
├── scripts/                 # Directory for scripts
│   └── Export-CALogs.ps1    # PowerShell script to export CA logs
SampleData/
├── sample_ca_logs.csv       # Sample CA log data for testing
LICENSE.md                   # Project license (MIT License)
README.md                    # This README file
```

---

## Features

- **Expanded ESC Misconfiguration Detection**: CertifEye detects potential abuses related to multiple ESC misconfigurations:
  - **ESC1**: Any Authenticated User Can Enroll
  - **ESC2**: No Manager Approval Required
  - **ESC3**: Unauthorized Accounts Enrolling for Machine Certificates
  - **ESC4**: Unauthorized Accounts Enrolling for Certificates with Client Authentication
  - **ESC6**: Abuse of Certificate Request Agent Permissions
- **Hybrid Machine Learning Approach**: Supports both supervised and unsupervised learning methods for anomaly detection.
- **Real-Time Monitoring**: Continuously scans CA logs to detect potential abuse as it happens.
- **Privileged Account Detection**: Flags certificates issued to high-privilege accounts.
- **Time-Based Anomalies**: Identifies requests made during unusual hours or at abnormal frequencies.
- **Template Vulnerability Identification**: Detects usage of vulnerable or misconfigured certificate templates.
- **Synthetic Data Augmentation**: Uses techniques like SMOTE to address class imbalance in supervised learning.
- **Comprehensive Logging**: Provides detailed logs for auditing and analysis.
- **Integration Ready**: Easily integrates with SIEM and SOAR platforms for centralized monitoring and automated response.
- **Customizable Alerts**: Configurable alerting mechanisms, including email notifications.

---

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/glides/CertifEye.git
   cd CertifEye
   ```

2. **Set Up a Virtual Environment (Optional but Recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use venv\Scripts\activate
   ```

3. **Install Dependencies**

   Install the required Python packages using `requirements.txt`:

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Configuration File (`config.yaml`)

Before running the scripts, ensure that `config.yaml` is properly configured with your environment-specific settings. The configuration file is included in the repository and contains settings such as:

- Paths to CA logs
- **Optionally**, known abuse request IDs
- High-value users/groups to monitor
- Vulnerable templates
- Templates requiring manager approval
- Authorized users for client authentication certificates
- **Training Mode**: Specify the training approach (`supervised`, `unsupervised`, or `hybrid`).
- SMTP settings for email alerts

#### **Training Mode Configuration**

The `training_mode` parameter in `config.yaml` allows you to specify the training approach:

- **`training_mode: "supervised"`**: Use supervised learning; requires known abuse cases (`known_abuse_request_ids` must be provided).
- **`training_mode: "unsupervised"`**: Use unsupervised anomaly detection; does not require known abuse cases.
- **`training_mode: "hybrid"`**: Combine both supervised and unsupervised methods.

If `known_abuse_request_ids` is empty or not provided, the script will default to unsupervised learning.

**Security Note:** Ensure that the `config.yaml` is secured and not exposed publicly, as it may contain sensitive information.

### Exporting CA Logs Using PowerShell

To ensure CertifEye has all the necessary data for accurate detection, it's important to collect comprehensive Certificate Authority (CA) logs that include fields such as the issued subject and SANs.

We have provided a PowerShell script `Export-CALogs.ps1` in the `scripts` directory to help you export these logs.

#### Steps to Export CA Logs

1. **Place the Script**

   - Copy the `Export-CALogs.ps1` script from the `scripts` directory to a location on your CA server.

2. **Adjust Parameters (Optional)**

   - The script accepts an optional parameter `-OutputCsv` to specify the export location.

     ```powershell
     # Example usage
     .\Export-CALogs.ps1 -OutputCsv "C:\Logs\exported_ca_logs.csv"
     ```

3. **Run the Script**

   - Open PowerShell **as an administrator**.
   - Navigate to the directory containing the script.
   - Execute the script:

     ```powershell
     .\Export-CALogs.ps1
     ```

4. **Verify the Exported Logs**

   - The logs will be saved to the path specified in `-OutputCsv`.
   - Open the CSV file to ensure it contains the expected data.

5. **Update `config.yaml`**

   - Ensure the `ca_logs_path` in your `config.yaml` file points to the exported logs:

     ```yaml
     paths:
       ca_logs_path: "C:/Logs/exported_ca_logs.csv"
     ```

#### Notes

- **Prerequisites**

  - The script uses `certutil`, which is included with Windows and does not require additional modules.

- **Execution Policy**

  - You may need to set the PowerShell execution policy to allow script execution:

    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope Process
    ```

- **Permissions**

  - Run the script with an account that has sufficient permissions to access the CA data.

- **Customization**

  - Adjust the properties and fields in the script if you need additional data.
  - Ensure that the column names in the exported CSV match those expected by CertifEye.

#### Security Considerations

- **Sensitive Data**: The exported logs may contain sensitive information. Handle the exported CSV file securely and restrict access as appropriate.

- **Compliance**: Ensure that exporting and analyzing CA logs complies with your organization's policies and any relevant regulations.

### Training the Model

With the comprehensive CA logs exported and `config.yaml` configured, you can now train the machine learning model.

1. **Set the Training Mode**

   - In `config.yaml`, set the `training_mode` parameter to `"supervised"`, `"unsupervised"`, or `"hybrid"` depending on your data availability and preference.
   - If you have known abuse cases, list their Request IDs in `known_abuse_request_ids`.

2. **Run the Training Script**

   ```bash
   python train_model.py
   ```

   - The script will output evaluation metrics to `train_model.log` and save the trained model (`certifeye_model.joblib`) and parameters (`certifeye_params.pkl`).
   - If using supervised learning, ensure that `known_abuse_request_ids` is populated with the Request IDs of known abuse cases.

### Detecting Abuse

1. **Ensure `config.yaml` is Updated**

   - The detection script uses the same `config.yaml` file.

2. **Run the Detection Script**

   ```bash
   python certifeye.py
   ```

   - The script will read from `config.yaml` and use the trained model to detect potential abuses.
   - Alerts will be logged in `certifeye.log` and can be configured to send email notifications.

3. **Configure Alerts**

   - Update SMTP settings in `config.yaml`.
   - Uncomment the `send_alert` line in `certifeye.py` to enable email notifications when potential abuse is detected.

---

## Notes on Detection

- **Anomaly Scores**:

  - In **unsupervised** mode, the model outputs anomaly scores instead of probabilities. Higher scores indicate a higher likelihood of anomalies.
  - The `abuse_prob` value in notifications represents the anomaly score.

- **Hybrid Approach**:

  - Combining supervised and unsupervised methods can enhance detection capabilities by leveraging both labeled data and anomaly detection techniques.
  - In **hybrid** mode, the supervised model will be trained on known abuse cases (if provided), while the unsupervised model will detect novel anomalies.

- **Alerts**:

  - Alerts will include the anomaly score or probability to help you assess the severity of the detected anomalies or potential abuses.

---

## Sample Data

A sample dataset (`sample_ca_logs.csv`) is provided in the `SampleData` directory for testing and demonstration purposes. This dataset includes both normal and abuse cases to help you understand how CertifEye processes and detects potential abuses.

**Note:** The sample data is fictional. In practice, you should use your own CA logs for accurate detection.

---

## Implementation Examples

### Integration with SIEM Platforms

CertifEye can be integrated into SIEM platforms like Splunk, IBM QRadar, or ArcSight for centralized monitoring.

**Splunk Integration Example:**

1. **Enable HTTP Event Collector (HEC) in Splunk**

2. **Configure CertifEye to Send Alerts to Splunk**

   ```python
   # In certifeye.py
   import requests

   def send_to_siem(alert_data):
       splunk_hec_url = 'https://your-splunk-server:8088/services/collector/event'
       splunk_token = 'YOUR_SPLUNK_HEC_TOKEN'
       headers = {'Authorization': f'Splunk {splunk_token}'}
       payload = {'event': alert_data, 'sourcetype': 'certifeye:alert'}

       response = requests.post(splunk_hec_url, headers=headers, json=payload, verify=False)
       if response.status_code == 200:
           logging.info('Event sent to Splunk successfully.')
       else:
           logging.error(f'Failed to send event to Splunk: {response.text}')
   ```

### Automated Alerting

**Email Alert Example:**

1. **Configure SMTP Settings in `config.yaml`**

   Ensure your SMTP settings are correctly specified in `config.yaml`.

2. **Enable Alerting in `certifeye.py`**

   ```python
   if prediction == 1:
       send_alert('security_team@yourdomain.com', new_request, probability, smtp_config)
   ```

---

## Contributing

Contributions are welcome!

1. **Fork the Repository**

2. **Create a Feature Branch**

   ```bash
   git checkout -b feature/YourFeature
   ```

3. **Commit Your Changes**

   ```bash
   git commit -m "Add your feature"
   ```

4. **Push to Your Branch**

   ```bash
   git push origin feature/YourFeature
   ```

5. **Open a Pull Request**

   - Ensure your code adheres to the project's coding standards.
   - Include appropriate unit tests.
   - Provide a clear description of the changes and the problem they solve.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE.md).

---

**Security Considerations**

- **Sensitive Information**: Ensure that any sensitive data, such as credentials, are secured and not committed to version control.
- **Compliance**: Always comply with your organization's policies and legal regulations when handling certificate data and logs.

---

## Acknowledgments

We appreciate the contributions from the open-source community and the support of our dedicated team members who made this project possible.

```