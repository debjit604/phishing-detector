"""
Utility functions for Advanced Phishing Detection
"""

import re
import ssl
import socket
import whois
import requests
import hashlib
import dns.resolver
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Tuple, Optional
import tldextract
from config import *

class URLScanner:
    """Advanced URL analysis for phishing detection"""
    
    @staticmethod
    def check_domain_reputation(domain: str) -> Dict:
        """Check domain against multiple reputation services"""
        reputation = {
            'domain': domain,
            'is_suspicious': False,
            'risk_score': 0,
            'reasons': []
        }
        
        # Check against known phishing domains (simulated)
        known_bad_domains = ['paypa1.com', 'amaz0n.net', 'g00gle.com']
        if domain.lower() in known_bad_domains:
            reputation['is_suspicious'] = True
            reputation['risk_score'] += 50
            reputation['reasons'].append('Known phishing domain')
        
        # Check for homograph attacks
        homograph_chars = {'0': 'o', '1': 'l', '5': 's', '8': 'b'}
        for char, replacement in homograph_chars.items():
            if char in domain:
                reputation['risk_score'] += 20
                reputation['reasons'].append(f'Homograph attack detected: {char} for {replacement}')
        
        return reputation
    
    @staticmethod
    def analyze_url_structure(url: str) -> Dict:
        """Deep analysis of URL structure"""
        analysis = {
            'url': url,
            'is_suspicious': False,
            'risk_factors': [],
            'security_score': 100
        }
        
        parsed = urlparse(url)
        
        # Check for IP-based URLs
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, parsed.netloc):
            analysis['risk_factors'].append('IP-based URL')
            analysis['security_score'] -= 30
        
        # Check for excessive subdomains
        subdomains = parsed.netloc.split('.')
        if len(subdomains) > 3:
            analysis['risk_factors'].append(f'Excessive subdomains: {len(subdomains)}')
            analysis['security_score'] -= 15
        
        # Check for @ symbol
        if '@' in url:
            analysis['risk_factors'].append('URL contains @ symbol')
            analysis['security_score'] -= 40
        
        # Check for URL encoding tricks
        if '%' in parsed.netloc:
            analysis['risk_factors'].append('URL encoding in domain')
            analysis['security_score'] -= 25
        
        # Check for data URIs
        if url.startswith('data:'):
            analysis['risk_factors'].append('Data URI scheme')
            analysis['security_score'] -= 50
        
        # Check for JavaScript in URL
        if 'javascript:' in url.lower():
            analysis['risk_factors'].append('JavaScript in URL')
            analysis['security_score'] -= 60
        
        # Analyze query parameters
        params = parse_qs(parsed.query)
        if len(params) > 5:
            analysis['risk_factors'].append('Excessive query parameters')
            analysis['security_score'] -= 10
        
        return analysis
    
    @staticmethod
    def check_ssl_certificate(domain: str) -> Dict:
        """Check SSL certificate validity"""
        ssl_info = {
            'has_ssl': False,
            'is_valid': False,
            'issuer': None,
            'expiry': None,
            'risk_score': 0
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['has_ssl'] = True
                    ssl_info['is_valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    
                    # Check expiry
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    ssl_info['expiry'] = expiry_date
                    
                    if expiry_date < datetime.now():
                        ssl_info['risk_score'] += 40
                    elif expiry_date < datetime.now() + timedelta(days=30):
                        ssl_info['risk_score'] += 20
        except Exception:
            ssl_info['risk_score'] += 30
        
        return ssl_info

class EmailHeaderAnalyzer:
    """Analyze email headers for phishing indicators"""
    
    @staticmethod
    def parse_headers(headers: str) -> Dict:
        """Parse and analyze email headers"""
        header_info = {
            'from': None,
            'reply_to': None,
            'return_path': None,
            'received_path': [],
            'authentication_results': {},
            'is_spoofed': False,
            'risk_factors': []
        }
        
        # Extract From
        from_match = re.search(r'From:\s*(.+)', headers, re.IGNORECASE)
        if from_match:
            header_info['from'] = from_match.group(1).strip()
        
        # Extract Reply-To
        reply_match = re.search(r'Reply-To:\s*(.+)', headers, re.IGNORECASE)
        if reply_match:
            header_info['reply_to'] = reply_match.group(1).strip()
        
        # Extract Return-Path
        return_match = re.search(r'Return-Path:\s*(.+)', headers, re.IGNORECASE)
        if return_match:
            header_info['return_path'] = return_match.group(1).strip()
        
        # Check for spoofing
        if header_info['from'] and header_info['reply_to']:
            from_domain = re.search(r'@([\w.]+)', header_info['from'])
            reply_domain = re.search(r'@([\w.]+)', header_info['reply_to'])
            
            if from_domain and reply_domain:
                if from_domain.group(1) != reply_domain.group(1):
                    header_info['is_spoofed'] = True
                    header_info['risk_factors'].append('Reply-To domain mismatch')
        
        # Extract SPF, DKIM, DMARC results
        spf_match = re.search(r'spf=(\w+)', headers, re.IGNORECASE)
        dkim_match = re.search(r'dkim=(\w+)', headers, re.IGNORECASE)
        dmarc_match = re.search(r'dmarc=(\w+)', headers, re.IGNORECASE)
        
        header_info['authentication_results'] = {
            'spf': spf_match.group(1) if spf_match else 'none',
            'dkim': dkim_match.group(1) if dkim_match else 'none',
            'dmarc': dmarc_match.group(1) if dmarc_match else 'none'
        }
        
        return header_info

class FeatureExtractor:
    """Advanced feature extraction engine"""
    
    @staticmethod
    def extract_linguistic_features(text: str) -> Dict:
        """Extract linguistic patterns indicating phishing"""
        features = {
            'urgency_score': 0,
            'fear_score': 0,
            'greed_score': 0,
            'authority_score': 0,
            'grammar_errors': 0,
            'spelling_mistakes': 0,
            'emotional_manipulation': 0
        }
        
        text_lower = text.lower()
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediately', 'now', 'today', 'limited', 'expire']
        features['urgency_score'] = sum(text_lower.count(word) for word in urgency_words)
        
        # Fear indicators
        fear_words = ['suspended', 'locked', 'unauthorized', 'security', 'violation', 'fraud']
        features['fear_score'] = sum(text_lower.count(word) for word in fear_words)
        
        # Greed indicators
        greed_words = ['won', 'prize', 'free', 'money', 'million', 'reward', 'claim']
        features['greed_score'] = sum(text_lower.count(word) for word in greed_words)
        
        # Authority indicators
        authority_words = ['official', 'government', 'irs', 'fbi', 'police', 'legal']
        features['authority_score'] = sum(text_lower.count(word) for word in authority_words)
        
        return features
    
    @staticmethod
    def extract_behavioral_features(text: str) -> Dict:
        """Extract behavioral patterns"""
        features = {
            'has_call_to_action': 0,
            'has_link_manipulation': 0,
            'has_attachment': 0,
            'is_personalized': 0,
            'has_brand_impersonation': 0
        }
        
        # Check for call to action
        cta_patterns = ['click here', 'download now', 'open attachment', 'visit', 'sign in']
        if any(pattern in text.lower() for pattern in cta_patterns):
            features['has_call_to_action'] = 1
        
        # Check for brand names
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix']
        for brand in brands:
            if brand in text.lower():
                features['has_brand_impersonation'] = 1
                break
        
        # Check for personalization
        if re.search(r'dear\s+\w+', text.lower()):
            features['is_personalized'] = 1
        
        return features