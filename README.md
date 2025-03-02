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
- [Security Considerations](#security-considerations)
- [Contact](#contact)

---

## Overview

**CertifEye** is a powerful tool designed to detect and prevent the abuse of Active Directory Certificate Services (AD CS) misconfigurations. By leveraging advanced machine learning algorithms, anomaly detection techniques, and rule-based logic, CertifEye analyzes CA logs to identify suspicious activities, potential exploits, and unauthorized privilege escalations. The system is flexible, scalable, and can be integrated into existing security infrastructures to enhance your organization's security posture.

---

## Project Structure

```
CertifEye/
├── certifeye/                  
│   ├── __init__.py
│   ├── certifeye.py                 # Main console application
│   ├── certifeye_utils.py           # Utility functions (centralized configuration, logging)
│   ├── detect_abuse.py              # Abuse detection module
│   ├── generate_synthetic_data.py   # Synthetic data generator
│   ├── prune_data.py                # Data pruning script
│   ├── train_model.py               # Model training script
├── scripts/
│   └── Export-CALogs.ps1            # PowerShell script to export CA logs
├── config.yaml                      # Configuration file
├── requirements.txt                 # Dependencies
├── LICENSE.md                       # Project license (MIT License)
└── README.md                        # This README file
```

---

## Features

- **Hybrid Detection Approach**: Combines rule-based detections with AI anomaly detection to identify both known and unknown abuse patterns.
- **Anomaly Detection**: Detects subtle indicators of potential abuse through advanced machine learning algorithms.
- **Human-Readable Explanations**: Provides clear, human-understandable explanations for detections, helping administrators understand and respond to potential security incidents.
- **Algorithm Flexibility**: Supports both Random Forest and XGBoost classifiers, selectable via configuration.
- **Real-Time Monitoring**: Continuously scans CA logs to detect potential abuse as it happens.
- **Privileged Account Detection**: Flags certificates issued to high-privilege accounts.
- **Time-Based Anomalies**: Identifies requests made during unusual hours or at abnormal frequencies.
- **Template Vulnerability Identification**: Detects usage of vulnerable or misconfigured certificate templates.
- **Comprehensive Logging**: Provides detailed logs for auditing and analysis, with standardized logging across all components.
- **Integration Ready**: Easily integrates with SIEM and SOAR platforms for centralized monitoring and automated response.
- **Customizable Alerts**: Configurable alerting mechanisms, including email notifications.
- **Centralized Configuration Management**: Simplifies configuration through a unified `config.yaml` file.

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

   **Note**: Ensure you have all necessary dependencies, including `xgboost`, `shap`, `imblearn`, `colorama`, `ruamel.yaml`, and `tqdm`.

---

## Usage

### Starting the CertifEye Console

To start the CertifEye console application:

```bash
python certifeye/certifeye.py
```

You'll see the following prompt:

```plaintext
Welcome to CertifEye. Type 'help' to list commands.

(CertifEye) >
```

### Available Commands

- `help`: List available commands.
- `generate_synthetic_data`: Generate synthetic CA log data.
- `train_model`: Train the machine learning model.
- `prune_data`: Prune the dataset.
- `detect_abuse`: Detect potential abuse.
- `exit`: Exit the CertifEye console.

#### **Command Usage**

- **Generate Synthetic Data**

  ```bash
  (CertifEye) > generate_synthetic_data --help
  ```

  **Example**:

  ```bash
  (CertifEye) > generate_synthetic_data -tr 1000 -ta 5 -dr 5000 -da 5 --update-config
  ```

  - `-tr 1000`: Generate 1000 training records.
  - `-ta 5`: Include 5 known abuse cases in the training data.
  - `-dr 5000`: Generate 5000 detection records.
  - `-da 5`: Include 5 known abuse cases in the detection data.
  - **Anomalies**: An additional 10 anomaly cases will be generated in both datasets.
  - `--update-config`: Update `config.yaml` with generated data.

- **Train the Model**

  ```bash
  (CertifEye) > train_model -v
  ```

- **Prune Data**

  ```bash
  (CertifEye) > prune_data --sample-size 3000
  ```

- **Detect Abuse**

  ```bash
  (CertifEye) > detect_abuse -v -f
  ```

**Note**: Commands support autocomplete for both commands and arguments.

---

## Configuration File (`config.yaml`)

Before running the scripts, ensure that `config.yaml` is properly configured with your environment-specific settings. The configuration file contains settings such as:

- **Paths**:
  - `ca_logs_full_path`: Path to the full CA logs CSV file.
  - `ca_logs_pruned_path`: Path where the pruned CA logs CSV will be saved.
  - `ca_logs_detection_path`: Path to the CA logs CSV file used for detection.
  - `model_output_path`: Path where the trained model will be saved.
  - `params_output_path`: Path where model parameters will be saved.

- **Known Request IDs**:
  - `known_abuse_request_ids`: List of Request IDs known to be abuses (used in training).
  - `known_good_request_ids`: List of Request IDs known to be legitimate.

- **Privileged Keywords**: Keywords associated with high-privilege accounts.

- **Vulnerable Templates**: List of vulnerable or misconfigured certificate templates.

- **Algorithm Selection**: Choose the machine learning algorithm.

  ```yaml
  algorithm: 'xgboost'  # Options: 'random_forest', 'xgboost'
  ```

- **Training Mode**: Specify the training approach (`supervised`, `unsupervised`, or `hybrid`).

- **SMTP Settings**: Configure email settings for alert notifications.

  **Security Note**: Do not store plaintext passwords in the configuration file. Use environment variables or a secrets manager to handle sensitive information.

- **Custom Thresholds**:
  - `validity_threshold`: Threshold in days for unusual certificate validity periods.
  - `request_volume_threshold`: Threshold for high request volumes.
  - `classification_threshold`: Threshold for classifying a request as an abuse.

- **Off-Hours Definition**:
  - `off_hours_start`: Start hour for off-hours (e.g., 22 for 10 PM).
  - `off_hours_end`: End hour for off-hours (e.g., 6 for 6 AM).

**Example Configuration:**

```yaml
paths:
  ca_logs_full_path: "C:/CA/exported_ca_logs.csv"
  ca_logs_pruned_path: "C:/CA/pruned_ca_logs.csv"
  ca_logs_detection_path: "C:/CA/new_requests.csv"
  model_output_path: "certifeye_model.joblib"
  params_output_path: "certifeye_params.pkl"

known_abuse_request_ids:
  - 10001
  - 10002
  - 10003
  - 10004
  - 10005

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
  - "ESC1"

templates_requiring_approval: []

authorized_client_auth_users: []

algorithm: 'xgboost'  # Options: 'random_forest', 'xgboost'

training_mode: "supervised"

smtp:
  server: 'smtp.yourdomain.com'
  port: 587
  username: 'alert@yourdomain.com'
  password: !ENV '${SMTP_PASSWORD}'  # Fetch from environment variable
  sender_email: 'alert@yourdomain.com'

validity_threshold: 730           # Validity threshold in days
request_volume_threshold: 50      # Request volume threshold
classification_threshold: 0.625   # Classification threshold

off_hours_start: 22               # Off-hours start hour
off_hours_end: 6                  # Off-hours end hour
```

**Security Note**: Ensure that `config.yaml` is secured and not exposed publicly, as it may contain sensitive information. Use environment variables or a secrets manager for credentials.

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
(CertifEye) > generate_synthetic_data -tr 1000 -ta 5 -dr 5000 -da 5 --update-config
```

- **Explanation**:
  - `-tr 1000`: Generate 1000 training records.
  - `-ta 5`: Include 5 known abuse cases in the training data.
  - `-dr 5000`: Generate 5000 detection records.
  - `-da 5`: Include 5 known abuse cases in the detection data.
  - **Anomalies**: An additional 10 anomaly cases will be generated in both datasets.
  - `--update-config`: Update `config.yaml` with generated data.

**Step 2: Prune Data**

```bash
(CertifEye) > prune_data --sample-size 3000
```

- **Explanation**:
  - `--sample-size 3000`: Sample 3000 normal requests for training.

**Step 3: Train the Model**

```bash
(CertifEye) > train_model -v
```

- **Explanation**:
  - `-v`: Increase verbosity to display more detailed output.

**Step 4: Detect Abuse**

```bash
(CertifEye) > detect_abuse -v -f
```

- **Explanation**:
  - `-v`: Increase verbosity for detailed output.
  - `-f`: Show feature contributions and explanations for detections.

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

## Security Considerations

- **Sensitive Information**: Ensure that any sensitive data, such as credentials, are secured and not committed to version control.
- **Compliance**: Always comply with your organization's policies and legal regulations when handling certificate data and logs.

**Disclaimer**: This tool is intended for authorized use only. Unauthorized or malicious use is strictly prohibited.

---

## Contact

For further assistance, please contact:

- **Email**: glid3s@protonmail.com
- **GitHub**: [glides](https://github.com/glides)

---

**Note**: For detailed information on each script and its usage, please refer to the comments within the scripts and ensure you have configured `config.yaml` appropriately.

---