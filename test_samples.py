"""
Test samples to demonstrate the extraordinary detection capabilities
"""

TEST_SCENARIOS = [
    {
        'name': 'Standard Business Email',
        'text': """Dear Team,
        
        Please find attached the quarterly report for Q1 2024.
        
        Meeting scheduled for Friday at 2 PM to discuss results.
        
        Best regards,
        John Smith
        Finance Director""",
        'headers': """From: john.smith@company.com
        To: team@company.com
        Subject: Q1 2024 Quarterly Report
        Authentication-Results: spf=pass; dkim=pass; dmarc=pass""",
        'expected': 'SAFE'
    },
    {
        'name': 'CEO Fraud / Business Email Compromise',
        'text': """URGENT WIRE TRANSFER REQUEST
        
        I need you to process a wire transfer of $50,000 immediately.
        
        This is a confidential acquisition, please don't discuss with anyone.
        
        Wire details:
        Bank: International Bank of Commerce
        Account: 1234567890
        Routing: 021000021
        
        Send confirmation once completed.
        
        Sent from my iPhone
        CEO""",
        'headers': """From: ceo@company-executive.com
        Reply-To: ceo@yahoo.com
        To: finance@company.com
        Subject: URGENT WIRE TRANSFER
        Authentication-Results: spf=fail; dkim=none; dmarc=none""",
        'expected': 'PHISHING'
    },
    {
        'name': 'Fake Invoice Scam',
        'text': """INVOICE #45892 - PAYMENT DUE
        
        Dear Accounts Payable,
        
        Attached is invoice #45892 for services rendered.
        
        Amount Due: $2,450.00
        Due Date: IMMEDIATE
        
        Please remit payment to:
        http://invoices-payment.tk/pay/45892
        
        Late fees will apply after 24 hours.
        
        Billing Department""",
        'headers': """From: billing@invoice-processing.tk
        To: ap@company.com
        Subject: INVOICE #45892 - PAYMENT DUE
        Authentication-Results: spf=softfail; dkim=none""",
        'expected': 'PHISHING'
    },
    {
        'name': 'Credential Harvesting - Office 365',
        'text': """Microsoft 365 Password Expiry Notification
        
        Your password will expire in 1 day(s).
        
        To keep your current password, click below:
        https://office365-verify.ml/keep-password
        
        Please do not ignore this email to avoid login interruption.
        
        Microsoft 365 Team""",
        'headers': """From: Microsoft 365 <admin@office365-verify.ml>
        To: user@company.com
        Subject: Password Expiry Notification
        Authentication-Results: spf=none; dkim=fail; dmarc=fail""",
        'expected': 'PHISHING'
    }
]

def run_tests():
    """Run test scenarios against the detector"""
    from advanced_phishing_detector import AdvancedPhishingDetector
    
    detector = AdvancedPhishingDetector()
    detector.load_model('extraordinary_phishing_model.pkl')
    
    print("\n" + "="*80)
    print("🧪 TESTING DETECTION CAPABILITIES")
    print("="*80)
    
    correct = 0
    total = len(TEST_SCENARIOS)
    
    for scenario in TEST_SCENARIOS:
        print(f"\n📧 Testing: {scenario['name']}")
        print("-" * 40)
        
        result = detector.predict_with_confidence(
            scenario['text'], 
            scenario['headers']
        )
        
        detected = 'SAFE' if 'SAFE' in result['prediction'] else 'PHISHING'
        is_correct = detected == scenario['expected']
        
        if is_correct:
            correct += 1
            print(f"✅ Correctly identified as: {result['prediction']}")
        else:
            print(f"❌ Failed: Got {result['prediction']}, expected {scenario['expected']}")
        
        print(f"   Confidence: {result['confidence']}")
        print(f"   Risk Score: {result['risk_score']:.1f}/100")
        print(f"   Risk Level: {result['risk_level']}")
    
    print(f"\n{'='*80}")
    print(f"📊 Results: {correct}/{total} correct ({correct/total*100:.1f}%)")
    print(f"{'='*80}")

if __name__ == "__main__":
    run_tests()