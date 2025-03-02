# Security Policy

## Supported Versions

We take security seriously and are committed to maintaining the security of CertifEye. The following versions of CertifEye are currently supported with security updates:

| Version   | Supported          |
| --------- | ------------------ |
| 0.9.x     | :white_check_mark: |
| < 0.9     | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in CertifEye, we appreciate your help in disclosing it to us in a responsible manner. **Please do not open a public issue or disclose the vulnerability publicly.**

**Contact Information:**

- **Email**: [glid3s@protonmail.com](mailto:glid3s@protonmail.com)

When reporting a vulnerability, please include the following information to help us address it promptly:

- **Description**: A detailed description of the vulnerability.
- **Reproduction Steps**: Step-by-step instructions to reproduce the issue.
- **Impact**: The potential impact and severity of the vulnerability.
- **Environment Details**: OS, Python version, CertifEye version, relevant configurations, etc.
- **Possible Fix**: If you have suggestions for a fix or have identified the root cause, please share them.

We aim to acknowledge your report within **48 hours** and will work with you to understand and resolve the issue as quickly as possible. We may reach out for additional information or clarification if needed.

## Coordinated Disclosure

We are committed to working with security researchers and the community on coordinated disclosure. Once a fix is implemented, we will:

- Release a security patch to address the vulnerability.
- Credit you for the discovery if you wish to be acknowledged.
- Publish a security advisory detailing the vulnerability and remediation steps.

## Security Updates

We will release security updates and patches via the official release channels:

- **GitHub Releases**: [CertifEye Releases](https://github.com/glides/CertifEye/releases)
- **PyPI**: [CertifEye Package](https://pypi.org/project/certifeye/)

Users are encouraged to keep their installations up to date to benefit from the latest security enhancements.

## Security Best Practices

To help keep your CertifEye deployment secure, please consider the following practices:

- **Secure Configuration**: Protect your `config.yaml` and other configuration files. Avoid committing sensitive information to version control.
- **Use Environment Variables**: Store sensitive credentials like SMTP passwords in environment variables rather than plaintext files.
- **Access Control**: Restrict access to your CertifEye installation to authorized personnel only.
- **Regular Updates**: Keep CertifEye and its dependencies updated to the latest versions.
- **Network Security**: Ensure that network communications are secured, especially if CertifEye is used in a distributed environment.

## Disclaimer

CertifEye is provided "as is" without warranty of any kind. Users are responsible for the security of their own systems and should use CertifEye at their own risk.

---
