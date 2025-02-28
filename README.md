# CertifEye

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

An AI-powered detection system for identifying potential abuse of Active Directory Certificate Services (AD CS) misconfigurations by analyzing Certificate Authority (CA) logs.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Starting the CertifEye Console](#starting-the-certifeye-console)
  - [Available Commands](#available-commands)
- [Configuration File (`config.yaml`)](#configuration-file-configyaml)
- [Exporting CA Logs Using PowerShell](#exporting-ca-logs-using-powershell)
- [Examples](#examples)
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
├── certifeye/                  
│   ├── __init__.py
│   ├── certifeye.py                 # Main console application
│   ├── certifeye_utils.py           # Utility functions
│   ├── detect_abuse.py              # Abuse detection module
│   ├── generate_synthetic_data.py   # Synthetic data generator
│   ├── prune_data.py                # Data pruning script
│   └── train_model.py               # Model training script
├── scripts/
│   └── Export-CALogs.ps1            # PowerShell script to export CA logs
├── config.yaml                      # Configuration file
├── requirements.txt                 # Dependencies
├── LICENSE.md                       # Project license (MIT License)
└── README.md                        # This README file
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
- **Synthetic Data Generation**: Provides a script to generate synthetic CA log data with configurable known abuses for testing and training.
- **Real-Time Monitoring**: Continuously scans CA logs to detect potential abuse as it happens.
- **Privileged Account Detection**: Flags certificates issued to high-privilege accounts.
- **Time-Based Anomalies**: Identifies requests made during unusual hours or at abnormal frequencies.
- **Template Vulnerability Identification**: Detects usage of vulnerable or misconfigured certificate templates.
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
   pip install -r certifeye/requirements.txt
   ```

---

## Usage

### Starting the CertifEye Console

To start the CertifEye console application:

```bash
python certifeye/certifeye.py
```

You'll see the following prompt:

```
Welcome to CertifEye. Type help or ? to list commands.

(CertifEye)
```

### Available Commands

- `help` or `?`: List available commands.
- `generate`: Generate synthetic CA log data.
- `train`: Train the machine learning model.
- `prune`: Prune the dataset.
- `detect`: Detect potential abuse.
- `exit`: Exit the CertifEye console.

#### **Command Usage**

- **Generate Synthetic Data**

  ```bash
  (CertifEye) generate
  ```

- **Train the Model**

  ```bash
  (CertifEye) train
  ```

- **Prune Data**

  ```bash
  (CertifEye) prune
  ```

- **Detect Abuse**

  ```bash
  (CertifEye) detect
  ```
---

## Configuration File (`config.yaml`)

Before running the scripts, ensure that `config.yaml` is properly configured with your environment-specific settings. The configuration file contains settings such as:

- Paths to CA logs
- Known abuse and good request IDs
- High-value users/groups to monitor
- Vulnerable templates
- Templates requiring manager approval
- Authorized users for client authentication certificates
- Training Mode: Specify the training approach (`supervised`, `unsupervised`, or `hybrid`).
- SMTP settings for email alerts
- Custom thresholds and definitions

**Example Configuration:**

```yaml
paths:
  ca_logs_full_path: "C:/CA/exported_ca_logs.csv"
  ca_logs_pruned_path: "C:/CA/pruned_ca_logs.csv"
  ca_logs_detection_path: "C:/CA/new_requests.csv"
  model_output_path: "certifeye_model.joblib"
  params_output_path: "certifeye_params.pkl"

known_abuse_request_ids:
  - 25611
  - 34321
  - 64308
  - 64309
  - 64490
  - 64491
  - 69306

known_good_request_ids:
  - 28311
  - 28323
  - 28609

privileged_keywords:
  - "Administrator"
  - "Admin"
  - "Domain Admins"
  - "Enterprise Admins"
  - "Schema Admins"
  - "krbtgt"
  - "Root"
  - "BackupAdmin"
  - "SecurityAdmin"

vulnerable_templates:
  - "SubCA"
  - "EnrollmentAgent"
  - "EnrollmentAgentOffline"
  - "DomainController"
  - "DirectoryEmailReplication"
  - "ESC1"
  - "LegacySmartcardLogon"
  - "ESC3"
  - "ESC2"

templates_requiring_approval: []

authorized_client_auth_users: []

training_mode: "hybrid"

smtp:
  server: 'smtp.yourdomain.com'
  port: 587
  username: 'alert@yourdomain.com'
  password: 'your_password'  # Secure this appropriately
  sender_email: 'alert@yourdomain.com'

validity_threshold: 730  # Validity threshold in days
request_volume_threshold: 50  # Request volume threshold
classification_threshold: 0.625  # Classification threshold

off_hours_start: 22  # Off-hours start hour
off_hours_end: 6     # Off-hours end hour
```

**Security Note:** Ensure that the `config.yaml` is secured and not exposed publicly, as it may contain sensitive information.

---

## Exporting CA Logs Using PowerShell

To ensure CertifEye has all the necessary data for accurate detection, it's important to collect comprehensive Certificate Authority (CA) logs that include fields such as the issued subject and SANs.

**Steps to Export CA Logs:**

1. **Place the Script**

   Copy `Export-CALogs.ps1` from the `scripts` directory to a location on your CA server.

2. **Run the Script**

   Open PowerShell **as an administrator** and execute:

   ```powershell
   .\Export-CALogs.ps1 -OutputCsv "C:\CA\exported_ca_logs.csv"
   ```

3. **Verify the Exported Logs**

   Ensure the logs are saved to the specified path and contain the expected data.

4. **Update `config.yaml`**

   Set the `ca_logs_full_path` in your `config.yaml`:

   ```yaml
   paths:
     ca_logs_full_path: "C:/CA/exported_ca_logs.csv"
   ```

---

## Examples

### **Using the CertifEye Console**

**Step 1: Generate Synthetic Data**

```bash
(CertifEye) generate
```

Follow the prompts or configure the parameters in `config.yaml`.

**Step 2: Prune Data (Optional)**

```bash
(CertifEye) prune
```

This step can help in reducing dataset size for faster training.

**Step 3: Train the Model**

```bash
(CertifEye) train
```

The model will be trained based on your configuration and saved to the specified path.

**Step 4: Detect Abuse**

```bash
(CertifEye) detect
```

The system will analyze requests and report any potential abuses.

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

## Acknowledgments

We appreciate the contributions from the open-source community and the support of our dedicated team members who made this project possible.

---

**Note:** For detailed information on each script and its usage, please refer to the comments within the scripts and ensure you have configured `config.yaml` appropriately.

---

For any issues or questions, please open an issue on the GitHub repository or reach out to the project maintainers.

---

### **Security Considerations**

- **Sensitive Information**: Ensure that any sensitive data, such as credentials, are secured and not committed to version control.
- **Compliance**: Always comply with your organization's policies and legal regulations when handling certificate data and logs.

---

**Disclaimer:** This tool is intended for authorized use only. Unauthorized or malicious use is strictly prohibited.

---

### **Contact**

For further assistance, please contact:

- **Email**: glid3s@protonmail.com
- **GitHub**: [glides](https://github.com/glides)

---
