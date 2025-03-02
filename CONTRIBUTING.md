# Contributing to CertifEye

First off, thank you for considering contributing to CertifEye! Your time and effort are greatly appreciated, and we value every contribution, whether it's reporting a bug, suggesting new features, improving documentation, or writing code.

This document provides guidelines to help you contribute effectively.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Setting Up the Development Environment](#setting-up-the-development-environment)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Submitting Changes](#submitting-changes)
- [Coding Guidelines](#coding-guidelines)
  - [Style Guide](#style-guide)
  - [Commit Messages](#commit-messages)
  - [Branching Model](#branching-model)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerabilities](#security-vulnerabilities)
- [License](#license)
- [Contact](#contact)

---

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand the expectations for contributors.

---

## Getting Started

### Prerequisites

- **Python 3.7 or higher**: CertifEye is developed using Python 3. Ensure you have Python 3.7 or higher installed.
- **Git**: Version control is handled via Git. Install Git from [here](https://git-scm.com/downloads).
- **Virtual Environment**: Using `venv` or `virtualenv` is recommended to manage dependencies.

### Setting Up the Development Environment

1. **Fork the Repository**

   Click the "Fork" button on the [CertifEye GitHub page](https://github.com/glides/CertifEye) to create your own copy of the repository.

2. **Clone Your Fork**

   ```bash
   git clone https://github.com/your-username/CertifEye.git
   cd CertifEye
   ```

3. **Set Up the Upstream Remote**

   ```bash
   git remote add upstream https://github.com/glides/CertifEye.git
   ```

4. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use venv\Scripts\activate
   ```

5. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

6. **Install Pre-commit Hooks (Optional but Recommended)**

   ```bash
   pip install pre-commit
   pre-commit install
   ```

---

## How to Contribute

### Reporting Bugs

If you find a bug in the project, please create an issue using the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md). Provide as much detail as possible to help us diagnose and fix the issue promptly.

**Steps:**

1. **Check for Existing Issues**

   Before creating a new issue, please search the existing issues to see if it has already been reported.

2. **Create a New Issue**

   Use the [GitHub Issues](https://github.com/glides/CertifEye/issues) tab to create a new bug report.

3. **Provide Detailed Information**

   - **Describe the Bug**: Provide a clear and concise description.
   - **To Reproduce**: List steps to reproduce the behavior.
   - **Expected Behavior**: Explain what you expected to happen.
   - **Environment Details**: OS, Python version, CertifEye version, etc.
   - **Logs and Screenshots**: Include any relevant logs or screenshots.

### Suggesting Enhancements

We welcome suggestions for new features or improvements. To suggest an enhancement, please open an issue using the **Feature Request** template.

**Provide:**

- **Use Case**: Explain the problem your suggestion would solve.
- **Proposal**: Describe your suggested enhancement in detail.
- **Alternatives**: Mention any alternative solutions you've considered.
- **Additional Context**: Add any other context or screenshots.

### Submitting Changes

If you want to contribute code, follow these steps:

1. **Create a New Branch**

   ```bash
   git checkout -b feature/YourFeatureName
   ```

2. **Make Your Changes**

   - Follow the coding guidelines specified below.
   - Write clear and concise code.
   - Include docstrings and comments where necessary.
   - Don't forget to update documentation if applicable.

3. **Commit Your Changes**

   ```bash
   git add .
   git commit -m "Add detailed description of your changes"
   ```

4. **Push to Your Fork**

   ```bash
   git push origin feature/YourFeatureName
   ```

5. **Create a Pull Request**

   - Go to your fork on GitHub.
   - Click the "Compare & pull request" button.
   - Provide a clear title and description for your PR.
   - Link to any relevant issues.

---

## Coding Guidelines

### Style Guide

- **PEP 8 Compliance**: Follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for Python code.
- **Naming Conventions**:
  - **Variables and Functions**: `snake_case`
  - **Classes**: `PascalCase`
- **Maximum Line Length**: 79 characters for code, 72 for comments/docstrings.
- **Imports**:
  - Group imports as per PEP 8: standard library, third-party libraries, local imports.
  - Absolute imports are preferred over relative imports.
- **Docstrings**: Use [Google Style](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html) for docstrings.

### Commit Messages

- **Format**: Use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format.
- **Structure**:
  ```
  type(scope): subject

  body (optional)

  footer (optional)
  ```
- **Types**:
  - `feat`: A new feature
  - `fix`: A bug fix
  - `docs`: Documentation changes
  - `style`: Code style changes (formatting, missing semi-colons, etc.)
  - `refactor`: Code changes that neither fix a bug nor add a feature
  - `test`: Adding or correcting tests
  - `chore`: Other changes that don't modify `src` or `test`

### Branching Model

- **Main Branch**: The stable version of the project.
- **Feature Branches**: Use the format `feature/YourFeatureName`.
- **Bug Fix Branches**: Use the format `bugfix/IssueNumber-ShortDescription`.
- **Hotfix Branches**: For critical fixes in the main branch, use `hotfix/ShortDescription`.

---

## Testing

- **Write Tests**: Ensure that you include tests for any new functionality or bug fixes.
- **Test Framework**: Use `unittest` or `pytest`.
- **Running Tests**: Provide instructions on how to run the test suite.
  ```bash
  python -m unittest discover tests
  ```
- **Coverage**: Aim for high test coverage. Use tools like `coverage.py` to measure.

---

## Pull Request Process

1. **Ensure All Tests Pass**

   Run the test suite and ensure all tests pass before submitting.

2. **Update Documentation**

   If your changes affect documentation, update it accordingly.

3. **Review Guidelines**

   - Your pull request will be reviewed by project maintainers.
   - Be responsive to feedback and make necessary changes.
   - Ensure that your pull request merges cleanly with the main branch.

---

## Security Vulnerabilities

If you discover a security vulnerability, **do not open an issue**. Instead, please contact us directly at:

- **Email**: glid3s@protonmail.com

We take security issues seriously and will address them promptly.

---

## License

By contributing to CertifEye, you agree that your contributions will be licensed under the [MIT License](LICENSE.md).

---

## Contact

For any questions or clarifications, feel free to reach out:

- **Email**: glid3s@protonmail.com
- **GitHub Issues**: [CertifEye Issues](https://github.com/glides/CertifEye/issues)

---

Thank you for your interest in contributing to CertifEye! Your efforts help make this project better for everyone.

---
