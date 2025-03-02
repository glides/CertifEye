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
  - [Using CertifEye with Your Own Data](#using-certifeye-with-your-own-data)
    - [Step 1: Export Your CA Logs](#step-1-export-your-ca-logs)
    - [Step 2: (Optional) Prune Data](#step-2-optional-prune-data)
    - [Step 3: Train the Model](#step-3-train-the-model)
    - [Step 4: Detect Abuse](#step-4-detect-abuse)
  - [Testing CertifEye with Synthetic Data (Optional)](#testing-certifeye-with-synthetic-data-optional)
    - [Step 1: Generate Synthetic Data](#step-1-generate-synthetic-data)
    - [Step 2: Train the Model with Synthetic Data](#step-2-train-the-model-with-synthetic-data)
    - [Step 3: Detect Abuse with Synthetic Data](#step-3-detect-abuse-with-synthetic-data)
  - [Configuration File (`config.yaml`)](#configuration-file-configyaml)
  - [Important Considerations](#important-considerations)
- [Exporting CA Logs Using PowerShell](#exporting-ca-logs-using-powershell)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Security Considerations](#security-considerations)
- [Contact](#contact)

---

## Overview

**CertifEye** is a powerful tool designed to detect and prevent the abuse of Active Directory Certificate Services (AD CS) misconfigurations, including multiple Enterprise Security Configuration (ESC) abuses. By leveraging advanced machine learning algorithms, anomaly detection techniques, and rule-based logic, CertifEye analyzes CA logs to identify suspicious activities, potential exploits, and unauthorized privilege escalations. The system is flexible, scalable, and can be integrated into existing security infrastructures to enhance your organization's security posture.

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

- **ESC Misconfiguration Detection**: CertifEye detects potential abuses related to multiple Enterprise Security Configuration (ESC) misconfigurations, helping to identify and prevent known vulnerabilities in AD CS.

- **Hybrid Detection Approach**: Combines rule-based detections with AI-driven anomaly detection to identify both known and unknown abuse patterns, enhancing detection capabilities.

- **Anomaly Detection**: Utilizes advanced machine learning algorithms to detect subtle indicators of potential abuse that may not be caught by rule-based methods alone.

- **Human-Readable Explanations**: Provides clear, understandable explanations for detections, helping administrators interpret and respond to potential security incidents effectively.

- **Privileged Account Detection**: Flags certificates issued to high-privilege accounts, alerting to potential unauthorized access or misuse.

- **Time-Based Anomaly Detection**: Identifies certificate requests made during unusual hours or at abnormal frequencies, which may indicate suspicious activities.

- **Template Vulnerability Identification**: Detects the use of vulnerable or misconfigured certificate templates that could be exploited for unauthorized access.

- **Comprehensive Logging**: Maintains detailed logs for auditing and analysis, with standardized logging across all components to facilitate troubleshooting and compliance.

- **Customizable Alerts**: Provides configurable alert mechanisms, including email notifications, allowing for timely responses to potential threats.

- **Centralized Configuration Management**: Simplifies setup and maintenance through a unified `config.yaml` file, enabling easy adjustments to settings and thresholds.


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

### Using CertifEye with Your Own Data

**Important Note:** In a production environment, you should use your actual CA logs to train the model and detect potential abuses. The synthetic data generation is intended for **testing purposes only**.

#### **Step 1: Export Your CA Logs**

Follow the instructions in the [Exporting CA Logs Using PowerShell](#exporting-ca-logs-using-powershell) section to export your CA logs from your production environment.

#### **Step 2: (Optional) Prune Data**

If your CA logs are very large and you need to reduce the dataset size for training, you can use the `prune_data` command to create a manageable subset.

```bash
(CertifEye) > prune_data --sample-size 3000
```

- **Explanation:**
  - `--sample-size 3000`: Sample 3000 normal requests for training.

This step is **optional** and only necessary if you need to reduce the size of your dataset. If you're working with smaller datasets or wish to use all available data, you can skip this step.

#### **Step 3: Train the Model**

```bash
(CertifEye) > train_model -v
```

- **Explanation:**
  - `-v`: Increase verbosity to display more detailed output.

This command trains the machine learning model using your pruned or full CA logs. Ensure that your `config.yaml` is properly configured with the paths to your CA logs.

#### **Step 4: Detect Abuse**

```bash
(CertifEye) > detect_abuse -v -f
```

- **Explanation:**
  - `-v`: Increase verbosity for detailed output.
  - `-f`: Show feature contributions and explanations for detections.

This command analyzes new CA logs to detect potential abuses using the trained model.

### Testing CertifEye with Synthetic Data (Optional)

If you wish to test CertifEye without using production data, you can generate synthetic data.

#### **Step 1: Generate Synthetic Data**

```bash
(CertifEye) > generate_synthetic_data -tr 1000 -ta 5 -dr 5000 -da 5 --update-config
```

- **Explanation:**
  - `-tr 1000`: Generate 1000 training records.
  - `-ta 5`: Include 5 known abuse cases in the training data.
  - `-dr 5000`: Generate 5000 detection records.
  - `-da 5`: Include 5 known abuse cases in the detection data.
  - **Anomalies**: An additional 10 anomaly cases will be generated in both datasets.
  - `--update-config`: Update `config.yaml` with generated data.

**Note:** Generating synthetic data is intended for **testing purposes only** and allows you to explore CertifEye's capabilities without using real CA logs. **You do not need to prune the synthetic data**, as the script allows you to specify the size of the generated datasets.

#### **Step 2: Train the Model with Synthetic Data**

```bash
(CertifEye) > train_model -v
```

- **Explanation:**
  - `-v`: Increase verbosity to display more detailed output.

When testing with synthetic data, this command trains the model using the generated synthetic training data.

#### **Step 3: Detect Abuse with Synthetic Data**

```bash
(CertifEye) > detect_abuse -v -f
```

- **Explanation:**
  - `-v`: Increase verbosity for detailed output.
  - `-f`: Show feature contributions and explanations for detections.

This analyzes the synthetic detection data using the model trained on synthetic data.

---

### Configuration File (`config.yaml`)

Ensure that `config.yaml` is correctly configured with paths to your own CA logs when working in production.

**Example Configuration:**

```yaml
paths:
  ca_logs_full_path: "C:/CA/exported_ca_logs.csv"         # Your actual CA logs
  ca_logs_pruned_path: "C:/CA/pruned_ca_logs.csv"         # Path for pruned logs (if pruning is used)
  ca_logs_detection_path: "C:/CA/new_requests.csv"        # New CA logs for detection
  model_output_path: "certifeye_model.joblib"
  params_output_path: "certifeye_params.pkl"

# Other configurations...
```

**Important Notes:**

- When testing with synthetic data, the paths in `config.yaml` are updated automatically if you use the `--update-config` flag with `generate_synthetic_data`.
- In a production environment, you should update `config.yaml` manually with the correct paths to your CA logs.

---

### Important Considerations

- **Data Privacy and Compliance:**
  - Ensure that you're compliant with your organization's policies and any legal regulations when handling CA logs and training data.
  - Sensitive information should be protected and not shared or exposed.

- **Model Retraining:**
  - Periodically retrain the model with updated CA logs to maintain detection accuracy as patterns and behaviors change over time.

- **Customization:**
  - Adjust thresholds and configurations in `config.yaml` to suit your environment and requirements.

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

## Contributing

Contributions are welcome!

Please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute to CertifEye.

---

## License

This project is licensed under the terms of the [MIT License](LICENSE.md).

---

## Acknowledgments

We appreciate the contributions from the open-source community and the support of our dedicated team members who made this project possible.

---

## Security Considerations

Please refer to the [SECURITY.md](SECURITY.md) file for information on how to report security vulnerabilities.

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
