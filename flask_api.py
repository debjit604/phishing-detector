"""
REST API for Phishing Detection Service
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import logging
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Load model
model = None

def load_model():
    """Load the trained model"""
    global model
    try:
        model = joblib.load('extraordinary_phishing_model.pkl')
        logging.info("Model loaded successfully")
    except Exception as e:
        logging.error(f"Failed to load model: {e}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Predict endpoint"""
    if not model:
        return jsonify({'error': 'Model not loaded'}), 500
    
    data = request.json
    email_text = data.get('text', '')
    email_headers = data.get('headers', '')
    
    if not email_text:
        return jsonify({'error': 'No email text provided'}), 400
    
    # Make prediction
    result = model.predict_with_confidence(email_text, email_headers)
    
    return jsonify(result)

@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    """Batch prediction endpoint"""
    if not model:
        return jsonify({'error': 'Model not loaded'}), 500
    
    data = request.json
    emails = data.get('emails', [])
    
    results = []
    for email in emails:
        result = model.predict_with_confidence(
            email.get('text', ''),
            email.get('headers', '')
        )
        results.append(result)
    
    return jsonify({'results': results})

if __name__ == '__main__':
    load_model()
    app.run(host='0.0.0.0', port=5000, debug=False)