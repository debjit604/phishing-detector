"""
REAL-TIME PHISHING SCANNER
===========================
Scans emails in real-time with:
- Email client integration
- API endpoint for web services
- Batch processing capability
- Real-time alert system
"""

import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Union
import pandas as pd
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class ScanResult:
    """Data class for scan results"""
    email_id: str
    timestamp: str
    prediction: str
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    phishing_probability: float
    safe_probability: float
    indicators: List[str]
    url_analysis: List[Dict]
    header_analysis: Optional[Dict]
    processing_time_ms: float
    recommendation: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        result = asdict(self)
        result['risk_level'] = self.risk_level.value
        return result
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), indent=2)

class RealTimeScanner:
    """Real-time phishing email scanner"""
    
    def __init__(self, detector, batch_size=100):
        self.detector = detector
        self.batch_size = batch_size
        self.scan_history = []
        self.alert_threshold = 70  # Risk score threshold for alerts
        
    def scan_email(self, email_text: str, email_headers: str = None, 
                   email_id: str = None) -> ScanResult:
        """Scan a single email in real-time"""
        start_time = time.time()
        
        # Generate email ID if not provided
        if not email_id:
            email_id = hashlib.md5(email_text.encode()).hexdigest()[:16]
        
        try:
            # Perform prediction
            result = self.detector.predict_with_confidence(email_text, email_headers)
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000
            
            # Create scan result
            scan_result = ScanResult(
                email_id=email_id,
                timestamp=datetime.now().isoformat(),
                prediction=result['prediction'],
                risk_level=RiskLevel[result['risk_level']],
                risk_score=result['risk_score'],
                confidence=float(result['confidence'].replace('%', '')),
                phishing_probability=float(result['phishing_probability'].replace('%', '')),
                safe_probability=float(result['safe_probability'].replace('%', '')),
                indicators=result.get('indicators', []),
                url_analysis=result.get('url_analysis', []),
                header_analysis=result.get('header_analysis'),
                processing_time_ms=round(processing_time, 2),
                recommendation=result.get('recommendation', '')
            )
            
            # Log result
            logger.info(f"Scanned email {email_id}: {scan_result.risk_level.value} "
                       f"(Score: {scan_result.risk_score:.1f})")
            
            # Check for alerts
            if scan_result.risk_score >= self.alert_threshold:
                self._send_alert(scan_result)
            
            # Add to history
            self.scan_history.append(scan_result)
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning email {email_id}: {str(e)}")
            raise
    
    def scan_batch(self, emails: List[Dict]) -> List[ScanResult]:
        """Scan a batch of emails"""
        logger.info(f"Starting batch scan of {len(emails)} emails...")
        
        results = []
        start_time = time.time()
        
        for i, email in enumerate(emails, 1):
            result = self.scan_email(
                email_text=email['text'],
                email_headers=email.get('headers'),
                email_id=email.get('id')
            )
            results.append(result)
            
            if i % 10 == 0:
                logger.info(f"Progress: {i}/{len(emails)} emails scanned")
        
        total_time = time.time() - start_time
        logger.info(f"Batch scan completed in {total_time:.2f}s "
                   f"({total_time/len(emails)*1000:.2f}ms per email)")
        
        return results
    
    def scan_from_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Scan emails from a DataFrame"""
        results = []
        
        for idx, row in df.iterrows():
            result = self.scan_email(
                email_text=row['text'],
                email_headers=row.get('headers'),
                email_id=row.get('id', f'email_{idx}')
            )
            results.append(result.to_dict())
        
        return pd.DataFrame(results)
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        if not self.scan_history:
            return {}
        
        results = self.scan_history
        total = len(results)
        
        stats = {
            'total_scanned': total,
            'phishing_detected': sum(1 for r in results if 'PHISHING' in r.prediction),
            'safe_emails': sum(1 for r in results if 'SAFE' in r.prediction),
            'risk_distribution': {
                level.value: sum(1 for r in results if r.risk_level == level)
                for level in RiskLevel
            },
            'avg_risk_score': np.mean([r.risk_score for r in results]),
            'avg_processing_time_ms': np.mean([r.processing_time_ms for r in results]),
            'high_risk_count': sum(1 for r in results if r.risk_score >= self.alert_threshold)
        }
        
        stats['detection_rate'] = (stats['phishing_detected'] / total * 100) if total > 0 else 0
        
        return stats
    
    def _send_alert(self, scan_result: ScanResult):
        """Send alert for high-risk emails"""
        alert_message = f"""
🚨 HIGH-RISK PHISHING EMAIL DETECTED 🚨
========================================
Email ID: {scan_result.email_id}
Risk Score: {scan_result.risk_score:.1f}/100
Risk Level: {scan_result.risk_level.value}
Confidence: {scan_result.confidence}%
Time: {scan_result.timestamp}

Indicators:
{chr(10).join(f'  ⚠️  {indicator}' for indicator in scan_result.indicators)}

Recommendation: {scan_result.recommendation}
========================================
"""
        logger.warning(alert_message)
        
        # Save alert to file
        with open('phishing_alerts.log', 'a') as f:
            f.write(alert_message + '\n')
    
    def export_results(self, filepath: str = 'scan_results.json'):
        """Export scan results to JSON"""
        results = [r.to_dict() for r in self.scan_history]
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results exported to {filepath}")
    
    def generate_report(self) -> str:
        """Generate a comprehensive scan report"""
        stats = self.get_statistics()
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║           PHISHING DETECTION SCAN REPORT                     ║
╚══════════════════════════════════════════════════════════════╝

📊 SCAN STATISTICS
==================
Total Emails Scanned: {stats.get('total_scanned', 0)}
Phishing Detected: {stats.get('phishing_detected', 0)}
Safe Emails: {stats.get('safe_emails', 0)}
Detection Rate: {stats.get('detection_rate', 0):.1f}%

📈 RISK DISTRIBUTION
====================
"""
        for level, count in stats.get('risk_distribution', {}).items():
            report += f"{level:10}: {count}\n"
        
        report += f"""
⚡ PERFORMANCE
==============
Average Risk Score: {stats.get('avg_risk_score', 0):.1f}/100
Average Processing Time: {stats.get('avg_processing_time_ms', 0):.2f}ms
High Risk Alerts: {stats.get('high_risk_count', 0)}

🕒 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        return report