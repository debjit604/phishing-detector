"""
Configuration settings for Advanced Phishing Detection System
"""

import os
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
MODELS_DIR = BASE_DIR / 'models'
LOGS_DIR = BASE_DIR / 'logs'

# Create directories
for dir_path in [DATA_DIR, MODELS_DIR, LOGS_DIR]:
    dir_path.mkdir(exist_ok=True)

# Model Configuration
MODEL_CONFIG = {
    'random_state': 42,
    'test_size': 0.2,
    'cv_folds': 5,
    'n_jobs': -1
}

# Advanced Feature Flags
FEATURE_FLAGS = {
    'use_deep_learning': True,
    'use_url_reputation': True,
    'use_domain_age_check': True,
    'use_ssl_analysis': True,
    'use_email_headers': True,
    'use_linguistic_analysis': True,
    'use_behavioral_patterns': True,
    'use_real_time_scanning': True
}

# Suspicious Indicators
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'suspend', 'limited', 'expire', 'confirm',
    'unauthorized', 'security alert', 'account locked', 'update immediately',
    'login attempt', 'unusual activity', 'click here', 'act now'
]
PHISHING_PATTERNS = [
    r'verify.*account',
    r'confirm.*password',
    r'update.*billing',
    r'limited.*access',
    r'suspicious.*activity',
    r'click.*link',
    r'login.*attempt'
]