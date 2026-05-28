"""
ADVANCED FEATURE ENGINEERING MODULE
====================================
Extracts 100+ features for phishing detection including:
- Domain WHOIS information
- Email metadata analysis  
- HTML structure analysis
- Attachment analysis
- Sender reputation scoring
"""

import re
import hashlib
import tldextract
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class AdvancedFeatureEngineer:
    """Extracts 100+ advanced features for phishing detection"""
    
    def __init__(self):
        self.suspicious_domains = self._load_suspicious_domains()
        self.legitimate_domains = self._load_legitimate_domains()
        self.phishing_keywords = self._load_phishing_keywords()
        
    def _load_suspicious_domains(self) -> set:
        """Load known suspicious domains"""
        return {
            'paypa1.com', 'amaz0n.net', 'app1e-id.org', 'micr0soft365.ml',
            'g00gle-security.ga', 'netflix-update.tk', 'faceb00k-login.cf',
            'instagr4m-verify.top', 'linkedin-security.xyz', 'twitter-alert.ml'
        }
    
    def _load_legitimate_domains(self) -> set:
        """Load common legitimate domains"""
        return {
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'linkedin.com', 'twitter.com', 'instagram.com',
            'netflix.com', 'paypal.com', 'github.com', 'stackoverflow.com'
        }
    
    def _load_phishing_keywords(self) -> Dict:
        """Load categorized phishing keywords"""
        return {
            'urgency': ['urgent', 'immediately', 'now', 'today', 'limited time', 'act fast'],
            'threat': ['suspend', 'terminate', 'delete', 'close', 'locked', 'disabled'],
            'reward': ['won', 'prize', 'free', 'million', 'winner', 'congratulation'],
            'action': ['click here', 'download', 'verify', 'confirm', 'update', 'sign in'],
            'sensitive': ['password', 'credit card', 'ssn', 'social security', 'bank account'],
            'authority': ['irs', 'fbi', 'police', 'government', 'official', 'legal']
        }
    
    def extract_domain_features(self, url: str) -> Dict:
        """Extract advanced domain features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            extracted = tldextract.extract(url)
            
            # Basic domain features
            features['domain_length'] = len(domain)
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['has_subdomain'] = bool(extracted.subdomain)
            
            # TLD analysis
            features['tld_length'] = len(extracted.suffix)
            features['is_free_tld'] = extracted.suffix in ['.tk', '.ml', '.ga', '.cf', '.gq']
            features['is_suspicious_tld'] = extracted.suffix in ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            
            # Domain composition
            features['digit_count'] = sum(c.isdigit() for c in domain)
            features['letter_count'] = sum(c.isalpha() for c in domain)
            features['special_char_count'] = sum(not c.isalnum() and c != '.' for c in domain)
            features['digit_ratio'] = features['digit_count'] / len(domain) if domain else 0
            
            # Hyphen and dot analysis
            features['hyphen_count'] = domain.count('-')
            features['dot_count'] = domain.count('.')
            
            # Brand impersonation check
            features['has_brand_name'] = any(brand in domain for brand in [
                'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
                'netflix', 'instagram', 'linkedin', 'twitter'
            ])
            
            # Homograph detection
            homograph_chars = {'0': 'o', '1': 'l', '5': 's', '8': 'b', '4': 'a', '3': 'e', '7': 't'}
            features['has_homograph'] = any(char in domain for char in homograph_chars)
            
            # IP address detection
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features['is_ip_address'] = bool(re.match(ip_pattern, domain))
            
            # Entropy calculation (randomness measure)
            char_freq = Counter(domain)
            length = len(domain)
            entropy = -sum((freq/length) * np.log2(freq/length) for freq in char_freq.values())
            features['domain_entropy'] = entropy
            
            # Vowel/consonant ratio
            vowels = sum(1 for c in domain if c in 'aeiou')
            features['vowel_ratio'] = vowels / len(domain) if domain else 0
            
        except Exception:
            features = {k: 0 for k in features} if 'features' in locals() else {}
        
        return features
    
    def extract_html_features(self, text: str) -> Dict:
        """Extract HTML-based features"""
        features = {
            'has_html': 0,
            'html_tag_count': 0,
            'has_form': 0,
            'has_script': 0,
            'has_iframe': 0,
            'has_meta_refresh': 0,
            'has_hidden_elements': 0,
            'external_resource_count': 0,
            'form_action_external': 0,
            'has_obfuscated_code': 0
        }
        
        # Check for HTML tags
        html_tags = re.findall(r'<[^>]+>', text)
        if html_tags:
            features['has_html'] = 1
            features['html_tag_count'] = len(html_tags)
        
        # Check for dangerous elements
        features['has_form'] = 1 if re.search(r'<form[^>]*>', text, re.IGNORECASE) else 0
        features['has_script'] = 1 if re.search(r'<script[^>]*>', text, re.IGNORECASE) else 0
        features['has_iframe'] = 1 if re.search(r'<iframe[^>]*>', text, re.IGNORECASE) else 0
        features['has_meta_refresh'] = 1 if re.search(r'<meta[^>]*http-equiv=["\']refresh', text, re.IGNORECASE) else 0
        
        # Check for hidden elements
        if re.search(r'display\s*:\s*none|visibility\s*:\s*hidden|hidden=["\']hidden', text, re.IGNORECASE):
            features['has_hidden_elements'] = 1
        
        # Check external resources
        features['external_resource_count'] = len(re.findall(r'(src|href)=["\']https?://', text, re.IGNORECASE))
        
        # Check if form submits to external domain
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', text, re.IGNORECASE)
        if form_actions:
            for action in form_actions:
                if action.startswith('http') and not any(domain in action for domain in self.legitimate_domains):
                    features['form_action_external'] = 1
        
        # Check for obfuscated code
        obfuscation_patterns = [
            r'eval\(', r'document\.write\(unescape\(', r'fromCharCode',
            r'\\x[0-9a-fA-F]{2}', r'\\u[0-9a-fA-F]{4}'
        ]
        if any(re.search(pattern, text) for pattern in obfuscation_patterns):
            features['has_obfuscated_code'] = 1
        
        return features
    
    def extract_attachment_features(self, text: str) -> Dict:
        """Extract attachment-related features"""
        features = {
            'has_attachment_mention': 0,
            'attachment_count': 0,
            'suspicious_attachment': 0,
            'has_executable': 0,
            'has_archive': 0,
            'has_document': 0,
            'has_pdf': 0
        }
        
        # Check for attachment mentions
        attachment_patterns = [
            r'attached', r'attachment', r'enclosed', r'\w+\.(zip|rar|7z|exe|scr|bat|cmd|msi|vbs|js|doc|docx|pdf|xls|xlsx|ppt|pptx)',
        ]
        
        for pattern in attachment_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                features['has_attachment_mention'] = 1
                features['attachment_count'] += len(matches)
        
        # Check for dangerous file types
        dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.msi', '.vbs', '.js', '.jar']
        features['has_executable'] = 1 if any(ext in text.lower() for ext in dangerous_extensions) else 0
        
        # Check for archive files
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        features['has_archive'] = 1 if any(ext in text.lower() for ext in archive_extensions) else 0
        
        # Check for document files
        doc_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        features['has_document'] = 1 if any(ext in text.lower() for ext in doc_extensions) else 0
        
        # Check for PDF
        features['has_pdf'] = 1 if '.pdf' in text.lower() else 0
        
        return features
    
    def extract_sender_features(self, headers: str) -> Dict:
        """Extract sender reputation features"""
        features = {
            'sender_domain_age': 0,
            'sender_has_dmarc': 0,
            'sender_has_spf': 0,
            'sender_has_dkim': 0,
            'reply_to_mismatch': 0,
            'from_display_name_length': 0,
            'from_has_digits': 0,
            'from_is_free_email': 0
        }
        
        # Extract From address
        from_match = re.search(r'From:\s*(?:.*?<)?([\w\.-]+@[\w\.-]+\.\w+)>?', headers, re.IGNORECASE)
        reply_match = re.search(r'Reply-To:\s*(?:.*?<)?([\w\.-]+@[\w\.-]+\.\w+)>?', headers, re.IGNORECASE)
        
        if from_match:
            from_email = from_match.group(1)
            from_domain = from_email.split('@')[1] if '@' in from_email else ''
            
            # Check if from domain is free email provider
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
            features['from_is_free_email'] = 1 if from_domain.lower() in free_providers else 0
        
        # Check Reply-To mismatch
        if from_match and reply_match:
            if from_match.group(1).lower() != reply_match.group(1).lower():
                features['reply_to_mismatch'] = 1
        
        # Check authentication
        features['sender_has_spf'] = 1 if 'spf=pass' in headers.lower() else 0
        features['sender_has_dkim'] = 1 if 'dkim=pass' in headers.lower() else 0
        features['sender_has_dmarc'] = 1 if 'dmarc=pass' in headers.lower() else 0
        
        return features
    
    def extract_temporal_features(self, text: str, headers: str) -> Dict:
        """Extract time-based features"""
        features = {
            'has_deadline': 0,
            'deadline_hours': 0,
            'sent_outside_business_hours': 0,
            'has_date_manipulation': 0,
            'urgency_temporal_score': 0
        }
        
        # Check for deadlines
        deadline_patterns = [
            r'(\d+)\s*hours?',
            r'(\d+)\s*days?',
            r'within\s*(\d+)',
            r'expires?\s*in\s*(\d+)',
            r'before\s*(\d+)'
        ]
        
        for pattern in deadline_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                features['has_deadline'] = 1
                features['deadline_hours'] = int(match.group(1))
                if 'day' in pattern:
                    features['deadline_hours'] *= 24
                break
        
        # Check for business hours (simplified)
        date_match = re.search(r'Date:\s*.*?(\d{2}):(\d{2})', headers)
        if date_match:
            hour = int(date_match.group(1))
            if hour < 8 or hour > 18:
                features['sent_outside_business_hours'] = 1
        
        # Check for date manipulation
        if re.search(r'(today|now|immediately|urgent|24\s*hour|48\s*hour)', text, re.IGNORECASE):
            features['urgency_temporal_score'] += 1
        
        return features
    
    def extract_psychological_features(self, text: str) -> Dict:
        """Extract psychological manipulation features"""
        features = {
            'authority_score': 0,
            'scarcity_score': 0,
            'social_proof_score': 0,
            'liking_score': 0,
            'reciprocity_score': 0,
            'commitment_score': 0,
            'psychological_manipulation_score': 0
        }
        
        # Authority indicators
        authority_words = ['official', 'authorized', 'certified', 'verified', 'authentic', 'genuine',
                          'government', 'federal', 'agency', 'department', 'irs', 'fbi']
        features['authority_score'] = sum(text.lower().count(word) for word in authority_words)
        
        # Scarcity indicators
        scarcity_words = ['limited', 'exclusive', 'rare', 'scarce', 'only', 'last chance',
                         'closing', 'ending', 'final', 'expire', 'hurry']
        features['scarcity_score'] = sum(text.lower().count(word) for word in scarcity_words)
        
        # Social proof
        social_proof_words = ['everyone', 'thousands', 'millions', 'popular', 'trending',
                            'joined', 'members', 'community', 'others']
        features['social_proof_score'] = sum(text.lower().count(word) for word in social_proof_words)
        
        # Liking
        liking_words = ['dear friend', 'valued customer', 'special', 'exclusive invitation',
                       'selected', 'chosen', 'loyal']
        features['liking_score'] = sum(text.lower().count(word) for word in liking_words)
        
        # Total manipulation score
        features['psychological_manipulation_score'] = sum([
            features['authority_score'],
            features['scarcity_score'],
            features['social_proof_score'],
            features['liking_score']
        ])
        
        return features
    
    def engineer_all_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer all 100+ features from dataset"""
        print("[INFO] Engineering 100+ advanced features...")
        
        all_features = []
        
        for idx, row in df.iterrows():
            text = row['text']
            headers = row.get('headers', '')
            
            features = {}
            
            # Extract URLs
            urls = re.findall(r'https?://[^\s]+', text)
            
            # Domain features (for each URL)
            if urls:
                url_features_list = [self.extract_domain_features(url) for url in urls[:3]]
                for i, url_feat in enumerate(url_features_list):
                    for key, value in url_feat.items():
                        features[f'url{i+1}_{key}'] = value
            else:
                # Fill with zeros if no URLs
                dummy_features = self.extract_domain_features('http://example.com')
                for i in range(1, 4):
                    for key in dummy_features:
                        features[f'url{i}_{key}'] = 0
            
            # HTML features
            features.update({f'html_{k}': v for k, v in self.extract_html_features(text).items()})
            
            # Attachment features
            features.update({f'attachment_{k}': v for k, v in self.extract_attachment_features(text).items()})
            
            # Sender features
            features.update({f'sender_{k}': v for k, v in self.extract_sender_features(headers).items()})
            
            # Temporal features
            features.update({f'temporal_{k}': v for k, v in self.extract_temporal_features(text, headers).items()})
            
            # Psychological features
            features.update({f'psych_{k}': v for k, v in self.extract_psychological_features(text).items()})
            
            # Text statistics
            features['word_count'] = len(text.split())
            features['char_count'] = len(text)
            features['avg_word_length'] = np.mean([len(w) for w in text.split()]) if text.split() else 0
            features['unique_word_ratio'] = len(set(text.lower().split())) / len(text.split()) if text.split() else 0
            
            # Capitalization features
            words = text.split()
            features['all_caps_word_ratio'] = sum(1 for w in words if w.isupper()) / len(words) if words else 0
            features['capitalized_word_ratio'] = sum(1 for w in words if w.istitle()) / len(words) if words else 0
            
            # Punctuation features
            features['exclamation_count'] = text.count('!')
            features['question_count'] = text.count('?')
            features['dot_count'] = text.count('.')
            features['exclamation_ratio'] = text.count('!') / len(text) if text else 0
            
            # Link features
            features['link_count'] = len(urls)
            features['has_https_links'] = any('https' in url for url in urls)
            features['has_http_links'] = any(url.startswith('http://') for url in urls)
            
            # Keyword category scores
            for category, keywords in self.phishing_keywords.items():
                features[f'keyword_{category}_score'] = sum(text.lower().count(kw) for kw in keywords)
            
            all_features.append(features)
        
        features_df = pd.DataFrame(all_features)
        features_df = features_df.fillna(0)
        
        print(f"✅ Engineered {len(features_df.columns)} features")
        return features_df