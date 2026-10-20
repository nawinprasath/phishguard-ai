# 🛡️ PhishGuard: AI-Powered Phishing URL Detection

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Vanilla JS](https://img.shields.io/badge/Frontend-Vanilla%20JS%20%26%20CSS-yellow.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

> **PhishGuard** is an end-to-end Machine Learning web application that detects phishing and malicious links in real-time. Instead of querying slow DNS servers or rendering hazardous web pages, PhishGuard extracts **13 lexical and structural URL features** to identify attack patterns with sub-millisecond latency.

---

## 📑 Table of Contents
- [Project Architecture](#-project-architecture)
- [Folder Structure](#-folder-structure)
- [Machine Learning Pipeline](#-machine-learning-pipeline)
- [Local Setup & Run](#-local-setup--run)
- [Free Cloud Deployment](#-free-cloud-deployment)
  - [Option A: Hugging Face Spaces (Recommended - 100% Free)](#option-a-hugging-face-spaces-recommended)
  - [Option B: Render (Free Web Service)](#option-b-render-free-web-service)
- [Interview & Portfolio Presentation Guide](#-interview--portfolio-presentation-guide)
- [Disclaimer](#-disclaimer)

---

## 🏛️ Project Architecture

```
User Input URL (Browser)
       │
       ▼
[ Flask REST API: POST /api/predict ]
       │
       ▼
[ Lexical Feature Extractor (feature_extractor.py) ]
  ├── Character metrics: Length, Dots, Hyphens, Digits, Special Characters
  ├── Security heuristics: Raw IP in Domain, '@' Authentication Trick, Double Slash
  └── Content heuristics: Subdomain Depth, Suspicious Keywords, URL Shorteners
       │
       ▼
[ Trained ML Pipeline (model.joblib) ]
  ├── Logistic Regression (Baseline)
  ├── Random Forest Classifier
  └── Gradient Boosting Classifier (Evaluated & Ranked by F1-Score)
       │
       ▼
[ JSON Response ] ──► [ Modern Glassmorphic UI ]
  ├── Prediction: Legitimate vs. Phishing
  ├── Model Confidence & 0-100 Threat Score
  └── "Why this result?" Feature-by-Feature Risk Breakdown
```

---

## 📂 Folder Structure

```
URL Detection/
│
├── feature_extractor.py   # Shared lexical feature extraction & risk explanation logic
├── train_model.py         # Model training, comparison, evaluation, & serialization
├── bootstrap_dataset.py   # Optional: generates starter benchmark dataset for quick testing
├── app.py                 # Flask backend API & web server
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation, deployment & interview guide
│
├── templates/
│   └── index.html         # Responsive, single-page application template
│
└── static/
    ├── css/
    │   └── style.css      # Vanilla CSS (Dark/Light mode, glassmorphism, animations)
    └── js/
        └── app.js         # Vanilla JS (Async API fetch, history tracking, dynamic UI)
```

---

## 🧪 Machine Learning Pipeline

### 1. Extracted Heuristic Features (13 Attributes)
| Feature Name | Description | Security Threat Context |
| :--- | :--- | :--- |
| `url_length` | Total characters in URL | Attackers pad URLs with random strings to obscure destination. |
| `hostname_length` | Total length of hostname | Long, convoluted hostnames often mimic authentic domains. |
| `count_dots` | Number of `.` characters | Phishers nest multiple subdomains to mimic brand URLs. |
| `count_hyphens` | Number of `-` characters | Hyphens are used in spoofing (e.g. `bank-of-america-login.com`). |
| `count_digits` | Total numerical digits | High digit counts correlate with session tokens or malicious IDs. |
| `count_special_chars` | Special characters (`@`, `?`, `=`, `&`, `_`, `%`) | Parameter manipulation and credential obfuscation. |
| `has_at_symbol` | Presence of `@` in URL | Browsers discard everything before `@` as login credentials. |
| `has_ip_address` | Hostname is an IPv4/IPv6 address | Raw IPs bypass DNS registration records and blacklist lookups. |
| `is_https` | Uses HTTPS protocol | HTTP links lack SSL encryption; still common in throwaway scam sites. |
| `count_subdomains` | Dot segments in hostname | Deep nesting (e.g., `paypal.com.verify.account.xyz`) misleads mobile viewers. |
| `suspicious_keyword_count` | Urgency keywords (`login`, `verify`, etc.) | Social engineering trigger words used in credential harvesting. |
| `is_shortened` | Known link shortener (e.g., `bit.ly`) | Conceals malicious hostnames from casual inspection. |
| `has_double_slash_path` | `//` in URL path | Triggers open redirects to third-party exploit servers. |

### 2. Model Benchmarking
`train_model.py` compares 3 classifiers under an **80/20 Stratified Split**:
1. **Logistic Regression** (L2 Regularized with `StandardScaler`)
2. **Random Forest Classifier** (100 Decision Trees, Gini Impurity)
3. **Gradient Boosting Classifier** (100 Boosting Stages, Residual Optimization)

The best model is selected based on **F1-Score**, serialized into `model.joblib`, and all real empirical metrics are saved into `metrics.json`.

---

## 🚀 Local Setup & Run

### Step 1: Clone or Navigate to the Directory
```bash
cd "c:\Users\nppra\Desktop\URL Detection"
```

### Step 2: Create a Virtual Environment (Recommended)
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Prepare the Dataset
You have two choices:

* **Choice A (Full Kaggle Dataset - Recommended for Portfolio):**
  1. Download the [Kaggle Phishing Site URLs Dataset](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls).
  2. Place the unzipped `phishing_site_urls.csv` directly inside the project root.

* **Choice B (Instant Bootstrap Dataset for Quick Testing):**
  Run the included bootstrap generator to create an initial test CSV of 120 verified real-world URLs:
  ```bash
  python bootstrap_dataset.py
  ```

### Step 5: Train the Models
```bash
python train_model.py
```
*Output: Evaluates all 3 models, prints Accuracy, Precision, Recall, F1, and confusion matrices, saves `model.joblib` and `metrics.json`.*

### Step 6: Start the Web App
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## ☁️ Free Cloud Deployment

Because this application uses a Python/Flask backend and Scikit-Learn inference, it cannot run on static web hosts like GitHub Pages. Here are two **100% free options**:

### Option A: Hugging Face Spaces (Recommended)
Hugging Face Spaces offers free 16GB RAM hosting for Machine Learning apps.

1. Create a free account at [huggingface.co](https://huggingface.co/).
2. Click **New Space** → Set Space Name (e.g. `phishguard-detector`).
3. Select **Space SDK**: **Docker** (or **Gradio/Flask**).
4. Create a `Dockerfile` in the root of your project:
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   EXPOSE 7860
   ENV PORT=7860
   CMD ["gunicorn", "-b", "0.0.0.0:7860", "app:app"]
   ```
5. Push your repository to the Hugging Face Git remote:
   ```bash
   git init
   git remote add origin https://huggingface.co/spaces/YOUR_USERNAME/phishguard-detector
   git add .
   git commit -m "Deploy PhishGuard"
   git push -u origin main
   ```
6. Hugging Face automatically builds the container and provides a free permanent public URL!

---

### Option B: Render (Free Web Service)
1. Push this project to a GitHub repository.
2. Sign in to [render.com](https://render.com/) with GitHub.
3. Click **New +** → **Web Service** → Connect your repository.
4. Configure the settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Instance Type**: `Free`
5. Click **Create Web Service**. Render builds and deploys your web app in 2 minutes.

---

## 🎤 Interview & Portfolio Presentation Guide

### 1. The Elevator Pitch (30-second STAR summary)
> *"For my college capstone portfolio, I developed **PhishGuard**, an AI-powered security application that classifies phishing URLs in under 3 milliseconds without issuing live HTTP requests. I engineered 13 lexical and structural URL features to detect domain spoofing, nested subdomains, and obfuscation tricks. After benchmarking Logistic Regression, Random Forest, and Gradient Boosting under an 80/20 stratified split, the ensemble model achieved high F1-score performance, which I packaged into an interactive Flask web application with a feature-level explainability breakdown."*

### 2. Common Technical Interview Questions & Answers

#### Q: "Why extract features only from the URL string instead of scraping the web page HTML?"
* **Answer**:
  1. **Safety**: Visiting an active malicious URL risks browser zero-day exploits, payload downloads, or drive-by infections.
  2. **Latency**: Scraping requires DNS resolution, TCP handshakes, TLS negotiation, and DOM rendering (taking 1.5–5 seconds per URL). Lexical extraction takes **less than 2 milliseconds**.
  3. **Takedown Resilience**: Many phishing sites are short-lived (taken down within 4–12 hours). Lexical analysis works on dead URLs and incoming traffic firewalls before a page is even rendered.

#### Q: "Why is F1-Score prioritized over Accuracy in phishing detection?"
* **Answer**:
  In cybersecurity datasets, legitimate URLs typically outnumber phishing links. A trivial model predicting "Legitimate" 100% of the time could appear 95% accurate while failing completely. **F1-Score** is the harmonic mean of Precision and Recall. It penalizes both False Positives (blocking real users from valid sites) and False Negatives (allowing attacks through).

#### Q: "How does the model handle zero-day domains?"
* **Answer**:
  Because lexical features evaluate **structural anomalies** (e.g. character density, subdomain depth, keyword urgency, and IP-based routing) rather than maintaining a static blacklist, it generalizes well to freshly registered domains that exhibit typical phishing design patterns.

---

## ⚠️ Disclaimer
PhishGuard is an academic machine learning portfolio project developed for educational demonstration. It uses lexical URL heuristics and should not be used as the sole defense mechanism against sophisticated cyber threats.
