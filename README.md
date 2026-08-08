# 🛡️ Authentication Log Analyzer

Authentication Log Analyzer is a Python-based authentication log analysis and threat detection tool designed to identify suspicious login behavior from authentication logs.

The analyzer processes failed and successful authentication events, applies time-window based detection rules, classifies suspicious authentication activity, assigns severity levels, and correlates successful logins that occur shortly after suspicious failures.

> **Project Status:** Portfolio / learning project focused on practical cybersecurity, detection engineering, and defensive programming.

---

## 🔍 Features

- Authentication log parsing
- Input validation for malformed log entries
- Invalid timestamp handling
- Failed and successful login tracking
- Time-window based attack detection
- Brute-force attack detection
- Multi-account attack detection
- Severity classification
- Successful-login correlation
- Possible account compromise detection
- Duplicate alert prevention
- Modular Python functions
- Automated pytest test suite

---

## 🚨 Detection Capabilities

### 1. Brute-Force Attack Detection

Authentication Log Analyzer detects repeated failed authentication attempts against the same account from the same IP address within the configured detection window.

Example:

```text
45.10.20.8
→ 10 failed attempts
→ Target: admin
→ Within 10 minutes
→ Possible Brute-Force Attack
→ Severity: HIGH
```

---

### 2. Multi-Account Attack Detection

The analyzer can identify suspicious activity where a single IP address generates failed authentication attempts against multiple user accounts.

Example:

```text
88.20.30.40

→ admin
→ rahul
→ priya
→ sriram
→ test

→ Possible Multi-Account Attack
→ Severity: MEDIUM
```

---

### 3. Successful Login After Suspicious Failures

The analyzer correlates successful authentication events with previously detected suspicious failures.

A successful login is treated as a possible account compromise indicator when it occurs after suspicious failures against the same account and from the same IP address within the configured correlation window.

Example:

```text
10 failed attempts against admin
        ↓
Brute-force activity detected
        ↓
admin successfully logs in
        ↓
40 seconds after the suspicious activity
        ↓
Possible Account Compromise Indicator
```

---

## ⚠️ Severity Classification

Authentication Log Analyzer assigns severity according to the number of failed authentication attempts.

| Failed Attempts | Severity |
|-----------------|----------|
| 5–9 | MEDIUM |
| 10–19 | HIGH |
| 20+ | CRITICAL |

The current minimum detection threshold is:

```text
5 failed attempts within 10 minutes
```

---

## ⏱️ Detection Windows

The analyzer uses time-based correlation to determine whether authentication events are related to the same suspicious activity.

```text
Attack Detection Window:
10 minutes

Successful Login Correlation Window:
15 minutes
```

A successful login is correlated only when:

- It occurs after the suspicious failed attempts.
- It occurs within the configured correlation window.
- The successful account was targeted during the suspicious activity.
- The successful login originates from the same IP address.

---

## 📄 Supported Log Format

Authentication Log Analyzer currently expects authentication events in the following format:

```text
YYYY-MM-DD HH:MM:SS EVENT user=<username> ip=<ip_address>
```

Example:

```text
2026-08-06 10:00:00 LOGIN_FAILED user=admin ip=45.10.20.8
2026-08-06 10:01:00 LOGIN_FAILED user=admin ip=45.10.20.8
2026-08-06 10:05:30 LOGIN_SUCCESS user=admin ip=45.10.20.8
```

### Supported Events

```text
LOGIN_FAILED
LOGIN_SUCCESS
```

Malformed log entries and invalid timestamps are rejected instead of being processed as valid authentication events.

---

## 🧠 How It Works

```text
Authentication Log
        ↓
Log Parser
        ↓
Input Validation
        ↓
Authentication Event Processing
        ↓
Time-Window Analysis
        ↓
Threshold Detection
        ↓
Attack Classification
        ↓
Severity Calculation
        ↓
Successful Login Correlation
        ↓
Security Alert
```

---

## 🧩 Main Components

The project separates major responsibilities into dedicated functions.

### `parse_log_line()`

Parses and validates individual authentication log entries.

### `calculate_severity()`

Determines the severity of suspicious activity based on failed-attempt counts.

### `determine_attack_type()`

Classifies suspicious authentication behavior such as brute-force and multi-account attacks.

### `find_correlated_success()`

Checks whether a successful login occurred after suspicious failures and determines whether it should be correlated with the detected activity.

### `analyze_logs()`

Coordinates the overall log-analysis workflow and generates security alerts.

---

## 🧪 Automated Testing

Authentication Log Analyzer includes an automated test suite built with **pytest**.

The current test suite contains:

```text
12 tests
12 passed
```

### Test Coverage

The automated tests cover:

- Severity classification boundaries
- Attack-type classification
- Valid log parsing
- Invalid timestamp handling
- Malformed log handling
- Successful-login correlation
- Different-user correlation prevention
- Brute-force detection
- Multi-account detection
- Successful-login-after-attack detection
- False-positive prevention
- Detection-window behavior

### Running the Test Suite

Install pytest if it is not already installed:

```bash
python -m pip install pytest
```

Then run the tests from the project directory:

```bash
python -m pytest -v
```

Current verified result:

```text
12 passed
```

---

## ▶️ Running Authentication Log Analyzer

### Requirements

- Python 3
- No third-party packages are required to run the core analyzer
- pytest is required only for running the automated test suite

### Run the Analyzer

Place authentication data inside:

```text
auth.log
```

Then execute:

```bash
python main.py
```

---

## 📂 Project Structure

```text
Authentication Log Analyzer/
│
├── main.py
├── auth.log
├── README.md
├── .gitignore
│
├── Screenshots/
│   └── Auth-demo.png
│
└── tests/
    └── test_analyzer.py
```

---

## 📊 Example Detection Output

```text
ALERT: Possible Brute-Force Attack
Severity: HIGH
IP Address: 45.10.20.8
Targeted Users: ['admin', 'admin', 'admin', 'admin', 'admin', ...]
Unique Users: {'admin'}
Number of Unique Users: 1
Failed Attempts: 10
Time Difference: 0:04:50

CRITICAL ALERT: Successful Login After Suspicious Failures!
IP Address: 45.10.20.8
User: admin
Previous Failed Attempts: 10
Successful Login Time: 2026-08-06 10:05:30
Time After Attack: 0:00:40
Possible Account Compromise Indicator

ALERT: Possible Multi-Account Attack
Severity: MEDIUM
IP Address: 88.20.30.40
Targeted Users: ['admin', 'rahul', 'priya', 'sriram', 'test']
Number of Unique Users: 5
Failed Attempts: 5
```

---

## 📸 Demo

Below is an example of Authentication Log Analyzer detecting suspicious authentication activity:

![Authentication Log Analyzer Demo](Screenshots/Auth-demo.png)

---

## 🛠️ Technologies Used

- **Python**
- **Pytest**
- **Git**
- **GitHub**
- File-based authentication log processing
- Rule-based security detection
- Time-based event correlation
- Automated testing

---

## 🎯 Security Concepts Demonstrated

This project demonstrates practical understanding of:

- Authentication security
- Security log analysis
- Detection engineering
- Brute-force detection
- Multi-account attack detection
- Event correlation
- Time-window analysis
- Severity classification
- Input validation
- Defensive programming
- False-positive reduction
- Modular software design
- Automated testing

---

## ⚠️ Current Limitations

Authentication Log Analyzer is currently a **portfolio and learning project**, not a production SIEM or enterprise security platform.

Current limitations include:

- File-based log ingestion
- Custom authentication log format
- Rule-based detection
- In-memory event processing
- No persistent database
- No real-time streaming pipeline
- No web dashboard
- No external threat-intelligence enrichment
- No centralized alert management

These limitations represent areas for future development rather than capabilities of the current version.

---

## 🚀 Future Roadmap

### Log Ingestion

- Real-time log monitoring
- Multiple log-source support
- JSON log ingestion
- Additional authentication log formats
- Streaming-based event ingestion

### Detection Engineering

- Additional authentication attack detections
- Configurable detection rules
- Configurable thresholds
- More advanced event correlation
- Improved alert deduplication
- Threat-intelligence enrichment

### Platform Development

- Persistent alert storage
- REST API
- Security monitoring dashboard
- Docker support
- SIEM-compatible event export
- Centralized alert management

---

## 📚 Project Purpose

Authentication Log Analyzer was developed to gain practical experience with:

- Python programming
- Authentication security
- Security log analysis
- Detection engineering
- Event correlation
- Time-window analysis
- Input validation
- Defensive programming
- Modular software architecture
- Automated testing

The project is intended to progressively evolve from a local authentication log analyzer into a more capable security monitoring and detection platform.

---

## 👨‍💻 Author

**Sriram**

Cybersecurity Student

GitHub: [sriram-cybersec](https://github.com/sriram-cybersec)