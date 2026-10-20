"""
PhishGuard - Flask Web Application (app.py)
===========================================
Production-ready Flask application serving the PhishGuard web interface and
REST API endpoints (/api/predict, /api/metrics, /api/health).
"""

import os
import json
import logging
from typing import Dict, Any, Tuple

from flask import Flask, request, jsonify, render_template, send_from_directory
import pandas as pd
import joblib

from feature_extractor import extract_features, explain_features, FEATURE_NAMES

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PhishGuard")

app = Flask(__name__, static_folder="static", template_folder="templates")

MODEL_PATH = "model.joblib"
METRICS_PATH = "metrics.json"

# In-memory storage for the loaded model package
MODEL_ARTIFACT = None


def load_model_package() -> bool:
    """
    Attempts to load the serialized model package from disk.
    Returns True if successfully loaded, False otherwise.
    """
    global MODEL_ARTIFACT
    if os.path.exists(MODEL_PATH):
        try:
            MODEL_ARTIFACT = joblib.load(MODEL_PATH)
            logger.info(f"Loaded ML model: {MODEL_ARTIFACT.get('model_name', 'Unknown')}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model from {MODEL_PATH}: {e}")
            MODEL_ARTIFACT = None
            return False
    else:
        logger.warning(f"Model file '{MODEL_PATH}' not found. Run train_model.py first.")
        MODEL_ARTIFACT = None
        return False


# Attempt loading model on startup
load_model_package()


@app.route("/")
def index():
    """Serves the single-page application."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint indicating model readiness."""
    is_ready = MODEL_ARTIFACT is not None
    return jsonify({
        "status": "online",
        "model_loaded": is_ready,
        "model_name": MODEL_ARTIFACT.get("model_name") if is_ready else None
    })


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """
    Returns real evaluation metrics generated during model training.
    """
    if not os.path.exists(METRICS_PATH):
        return jsonify({
            "status": "not_trained",
            "message": "Model has not been trained yet. Please run 'python train_model.py' to generate real metrics."
        }), 404

    try:
        with open(METRICS_PATH, "r") as f:
            metrics_data = json.load(f)
        return jsonify(metrics_data)
    except Exception as e:
        logger.error(f"Error reading {METRICS_PATH}: {e}")
        return jsonify({"error": "Failed to read metrics file"}), 500


@app.route("/api/predict", methods=["POST"])
def predict():
    """
    Analyzes an input URL and returns classification, confidence score,
    and a deep-dive lexical feature breakdown.
    """
    global MODEL_ARTIFACT

    # Try lazy-loading if model was not loaded on boot
    if MODEL_ARTIFACT is None:
        if not load_model_package():
            return jsonify({
                "error": "Model not trained yet",
                "message": "Please execute 'python train_model.py' to train and save the model before scanning."
            }), 503

    # Parse and validate request
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    data = request.get_json()
    raw_url = data.get("url", "")

    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({"error": "URL cannot be empty."}), 400

    target_url = raw_url.strip()

    # Basic structural check
    if len(target_url) < 3 or ("." not in target_url and "/" not in target_url):
        return jsonify({"error": "Please provide a valid URL string (e.g. 'https://example.com')."}), 400

    try:
        # 1. Extract numerical features
        features_dict = extract_features(target_url)

        # 2. Build aligned DataFrame for Scikit-Learn
        feature_df = pd.DataFrame([features_dict])[FEATURE_NAMES]

        # 3. Apply scaling if the model requires it
        clf = MODEL_ARTIFACT["model"]
        scaler = MODEL_ARTIFACT["scaler"]
        requires_scaling = MODEL_ARTIFACT.get("requires_scaling", False)

        if requires_scaling and scaler is not None:
            input_vector = scaler.transform(feature_df)
        else:
            input_vector = feature_df

        # 4. Predict probabilities (class 0: Legitimate, class 1: Phishing)
        if hasattr(clf, "predict_proba"):
            probabilities = clf.predict_proba(input_vector)[0]
            phishing_prob = float(probabilities[1])
        else:
            prediction_class = int(clf.predict(input_vector)[0])
            phishing_prob = 1.0 if prediction_class == 1 else 0.0

        # Determine verdict (threshold = 0.50)
        is_phishing = phishing_prob >= 0.50
        prediction_label = "Phishing" if is_phishing else "Legitimate"

        # Calculate user-facing confidence and risk score
        confidence_percentage = round((phishing_prob if is_phishing else (1.0 - phishing_prob)) * 100, 2)
        risk_score = int(round(phishing_prob * 100))

        # Categorize risk severity
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Moderate"
        elif risk_score >= 10:
            risk_level = "Low"
        else:
            risk_level = "Safe"

        # 5. Generate human-readable feature explanation breakdown
        feature_breakdown = explain_features(target_url, features_dict)

        return jsonify({
            "url": target_url,
            "prediction": prediction_label,
            "is_phishing": is_phishing,
            "confidence": confidence_percentage,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "model_used": MODEL_ARTIFACT.get("model_name", "Classifier"),
            "features": feature_breakdown
        })

    except Exception as e:
        logger.exception(f"Inference error for URL '{target_url}': {e}")
        return jsonify({"error": "Failed to analyze URL due to internal server error."}), 500


if __name__ == "__main__":
    # Support dynamic port for cloud deployments (Render, Hugging Face, Heroku)
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[+] PhishGuard Server running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
