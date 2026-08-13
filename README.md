# password-security-risk-analyzer
# Password Security Analyzer and Risk Assessment Tool

A client-side cybersecurity tool that analyzes password strength, detects common security weaknesses, estimates entropy, and provides an overall security score with recommendations.

## Overview

Most password checkers only show whether a password is Weak, Medium, or Strong.

This project provides a more detailed analysis by checking password length, character diversity, predictable patterns, common passwords, and estimated entropy.

The entire analysis is performed locally in the browser, so passwords are not uploaded to a server or sent to external APIs.

## Features

* **Security Score** – Calculates a score from 0–100.
* **Password Strength** – Shows Weak, Moderate, Strong, or Very Strong.
* **Password Entropy** – Provides an estimated entropy value.
* **Character Analysis** – Checks uppercase, lowercase, numbers, and special characters.
* **Pattern Detection** – Detects sequences, repeated characters, keyboard patterns, and predictable years.
* **Common Password Detection** – Checks passwords against a local list of commonly used passwords.
* **Security Recommendations** – Provides suggestions based on detected weaknesses.
* **Brute-Force Resistance** – Gives an educational estimate of password resistance.
* **Secure Password Generator** – Generates passwords using `crypto.getRandomValues()`.
* **Passphrase Generator** – Generates longer and easier-to-remember passphrases.
* **Password Comparison** – Compares the security characteristics of two passwords.
* **Analysis History** – Stores only password statistics locally, never the actual password.
* **Cybersecurity Education** – Explains common password attacks such as brute force and dictionary attacks.

## Technologies Used

* HTML5
* CSS3
* JavaScript
* Browser Web APIs
* LocalStorage

No backend, database, or external API is required.

## How It Works

The analyzer evaluates a password using several factors:

### 1. Password Length

Longer passwords generally provide a larger number of possible combinations.

### 2. Character Diversity

The tool checks whether the password contains:

* Uppercase letters
* Lowercase letters
* Numbers
* Special characters

### 3. Entropy

The project estimates password entropy using the size of the character pool and password length.

```text
Entropy ≈ Length × log2(Character Pool)
```

This is an estimate and does not represent guaranteed real-world cracking time.

### 4. Pattern Detection

The analyzer detects predictable patterns such as:

* `123456`
* `abcdef`
* `qwerty`
* Repeated characters
* Repeated words
* Common years
* Predictable character substitutions

### 5. Security Score

The different analysis results are combined into an explainable score from **0–100**.

The score is based on factors such as password length, entropy, character diversity, common-password matches, and predictable patterns.

## Privacy

Privacy is an important part of this project.

* Passwords are analyzed locally in the browser.
* Passwords are not uploaded to a server.
* Passwords are not stored in a database.
* Passwords are not sent to external APIs.
* Analysis history stores only statistics such as score and entropy.

## Screenshots

### Password Analyzer

*Add screenshot here.*

### Security Analysis

*Add screenshot here.*

### Password Generator

*Add screenshot here.*

## How to Run

### Option 1 — Open Directly

Download the project and open:

```text
index.html
```

in your browser.

### Option 2 — VS Code Live Server

1. Open the project in VS Code.
2. Install the **Live Server** extension.
3. Right-click `index.html`.
4. Select **Open with Live Server**.

No installation or build process is required.

## Project Structure

```text
Password-Security-Analyzer/
│
├── index.html
├── style.css
├── script.js
├── README.md
└── assets/
```

## Limitations

* The common-password list is a small local dataset.
* Entropy and brute-force calculations are theoretical estimates.
* Pattern detection cannot identify every possible password pattern.
* The project does not check real-world breach databases because it does not use external APIs.

## Future Enhancements

* Larger password datasets
* More advanced pattern detection
* Offline breach-dataset analysis
* Additional password security metrics
* Exportable security reports

## Disclaimer

This project is developed for educational cybersecurity purposes.

It does not perform password cracking or attacks against real systems.
