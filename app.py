from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import os
import json
from threatnet import ThreatNetEngine
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'threat-net-ultra-secure-key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

engine = ThreatNetEngine()

# In a real app, this would be in a DB
current_alerts = []
session_history = []
USERS = {
    'admin': 'password',
    'shree': '123',
    'mihir': '123',
    'gaurav': '123',
    'shiv': '123',
    'shikha': '123',
    'vaishnavi': '123'
}

TRANSLATIONS = {
    'en': {
        'title': 'ThreatNet - Intelligence Dashboard',
        'heading': 'THREAT',
        'subheading': 'NET',
        'subtitle': 'Command Interface v1.2',
        'secured_session': 'SECURED SESSION',
        'terminate': 'TERMINATE',
        'total_signals': 'Total Signals',
        'telemetry': 'Telemetry ingestion',
        'critical': 'Critical',
        'threats': 'Direct adversarial threats',
        'suspicious': 'Suspicious',
        'anomalous': 'Anomalous behavioral patterns',
        'system_info': 'System Info',
        'operational_log': 'Operational log data',
        'visualization': 'Threat Visualization Baseline',
        'source_mgmt': 'Intelligence Source Management',
        'file_upload': 'FILE UPLOAD',
        'paste_btn': 'CODE/TEXT PASTE',
        'file_source': 'File Source',
        'log_signature': 'Log Signature',
        'analyze_btn': 'Analyze Source',
        'paste_label': 'Paste Raw Log Data',
        'paste_placeholder': 'Paste log lines here...',
        'ingest_btn': 'Ingest Paste',
        'tools_title': 'Additional Security Tools',
        'encode_decode': 'Encode/Decode: Encoding and decoding functions for debugging web-related problems.',
        'encode': 'Encode',
        'decode': 'Decode',
        'live_timeline': 'Live Intelligence Timeline',
        'search_placeholder': 'Search parameters...',
        'all_sources': 'All Sources',
        'export_json': 'EXPORT JSON',
        'timestamp': 'Timestamp',
        'level': 'Level',
        'incident': 'Incident',
        'reasoning': 'Reasoning (AI)',
        'evidence': 'Evidence (Log Line)',
        'mitigation': 'Mitigation',
        'no_logs': 'No log sources analyzed. Upload a file to begin detection.',
        'faq': 'FAQ',
        'login': 'Login',
        'username': 'Access ID',
        'password': 'Security Key',
        'signin': 'Sign In',
        'no_account': "Don't have an access key?",
        'request_access': 'Request Access',
        'already_have': 'Already have an Access ID?',
        'create_account': 'Create Account',
        'change_lang': 'Language',
        'english': 'English',
        'hindi': 'हिन्दी',
        'gujarati': 'ગુજરાતી',
        'kb_title': 'Knowledge Base',
        'kb_subtitle': 'Frequently Asked Questions & System Introduction',
        'faq1_q': 'What log formats are supported?',
        'faq1_a': 'Script auto-detects common formats (ISO 8601, Apache/Nginx, Syslog, JSON, etc.) to extract key fields.',
        'faq2_q': 'How does the log analysis work? Is my data sent anywhere?',
        'faq2_a': 'The analysis happens in two stages. First, a small sample of your logs (up to 50 lines) is sent to our server for a quick validation to determine the log structure and generate parsing rules. <br><br> Then, the full log data is processed entirely within your browser. Your complete log data never leaves your machine for the standard parsing and aggregation.',
        'faq3_q': 'What insights does the analysis provide?',
        'faq3_a': 'Get a dashboard view of log counts, errors, and anomalies. Explore trends with charts for time distribution, status codes, request paths, IPs, and response times.',
        'faq4_q': 'Are there log size limitations?',
        'faq4_a': 'No hard limit, but logs over 1MB trigger a warning. Since analysis runs in your browser, very large logs can impact performance depending on your machine.',
        'faq5_q': 'What if parsing fails for my logs?',
        'faq5_a': 'Auto-detection covers common formats well. If it struggles with your custom format, ensure key elements like timestamps are clear.'
    },
    'hi': {
        'title': 'थ्रेटनेट - इंटेलिजेंस डैशबोर्ड',
        'heading': 'थ्रेट',
        'subheading': 'नेट',
        'subtitle': 'कमांड इंटरफेस v1.2',
        'secured_session': 'सुरक्षित सत्र',
        'terminate': 'समाप्त करें',
        'total_signals': 'कुल सिग्नल',
        'telemetry': 'टेलीमेट्री अंतर्ग्रहण',
        'critical': 'गंभीर',
        'threats': 'प्रत्यक्ष प्रतिकूल खतरे',
        'suspicious': 'संदिग्ध',
        'anomalous': 'विषम व्यवहार पैटर्न',
        'system_info': 'सिस्टम जानकारी',
        'operational_log': 'परिचालन लॉग डेटा',
        'visualization': 'खतरा विज़ुअलाइज़ेशन बेसलाइन',
        'source_mgmt': 'खुफिया स्रोत प्रबंधन',
        'file_upload': 'फ़ाइल अपलोड',
        'paste_btn': 'कोड/टेक्स्ट पेस्ट',
        'file_source': 'फ़ाइल स्रोत',
        'log_signature': 'लॉग हस्ताक्षर',
        'analyze_btn': 'स्रोत का विश्लेषण करें',
        'paste_label': 'रॉ लॉग डेटा पेस्ट करें',
        'paste_placeholder': 'यहां लॉग लाइनें पेस्ट करें...',
        'ingest_btn': 'पेस्ट इनगेस्ट करें',
        'tools_title': 'अतिरिक्त सुरक्षा उपकरण',
        'encode_decode': 'एन्कोड/डिकोड: वेब-संबंधित समस्याओं के डिबगिंग के लिए एन्कोडिंग और डिकोडिंग फ़ंक्शन।',
        'encode': 'एन्कोड',
        'decode': 'डिकोड',
        'live_timeline': 'लाइव इंटेलिजेंस टाइमलाइन',
        'search_placeholder': 'खोज पैरामीटर...',
        'all_sources': 'सभी स्रोत',
        'export_json': 'निर्यात JSON',
        'timestamp': 'समय-सीमा',
        'level': 'स्तर',
        'incident': 'घटना',
        'reasoning': 'तर्क (AI)',
        'evidence': 'साक्ष्य (लॉग लाइन)',
        'mitigation': 'शमन',
        'no_logs': 'किसी लॉग स्रोत का विश्लेषण नहीं किया गया। पहचान शुरू करने के लिए एक फ़ाइल अपलोड करें।',
        'faq': 'सामान्य प्रश्न',
        'login': 'लॉगिन',
        'username': 'एक्सेस आईडी',
        'password': 'सुरक्षा कुंजी',
        'signin': 'साइन इन करें',
        'no_account': 'एक्सेस कुंजी नहीं है?',
        'request_access': 'एक्सेस का अनुरोध करें',
        'already_have': 'क्या आपके पास पहले से एक्सेस आईडी है?',
        'create_account': 'खाता बनाएं',
        'change_lang': 'भाषा',
        'english': 'English',
        'hindi': 'हिन्दी',
        'gujarati': 'ગુજરાતી'
    },
    'gu': {
        'title': 'થ્રેટનેટ - ઇન્ટેલિજન્સ ડેશબોર્ડ',
        'heading': 'થ્રેટ',
        'subheading': 'નેટ',
        'subtitle': 'કમાન્ડ ઈન્ટરફેસ v1.2',
        'secured_session': 'સુરક્ષિત સત્ર',
        'terminate': 'સમાપ્ત કરો',
        'total_signals': 'કુલ સિગ્નલ',
        'telemetry': 'ટેલીમેટ્રી ઇન્જેશન',
        'critical': 'ગંભીર',
        'threats': 'સીધા પ્રતિકૂળ જોખમો',
        'suspicious': 'શંકાસ્પદ',
        'anomalous': 'અસાધારણ વર્તણૂક પેટર્ન',
        'system_info': 'સિસ્ટમ માહિતી',
        'operational_log': 'ઓપરેશનલ લોગ ડેટા',
        'visualization': 'થ્રેટ વિઝ્યુલાઇઝેશન બેઝલાઇન',
        'source_mgmt': 'ઇન્ટેલિજન્સ સોર્સ મેનેજમેન્ટ',
        'file_upload': 'ફાઇલ અપલોડ',
        'paste_btn': 'કોડ/ટેક્સ્ટ પેસ્ટ',
        'file_source': 'ફાઇલ સ્ત્રોત',
        'log_signature': 'લોગ હસ્તાક્ષર',
        'analyze_btn': 'સ્ત્રોતનું વિશ્લેષણ કરો',
        'paste_label': 'કાચો લોગ ડેટા પેસ્ટ કરો',
        'paste_placeholder': 'અહીં લોગ લાઈનો પેસ્ટ કરો...',
        'ingest_btn': 'પેસ્ટ ઇન્જેસ્ટ કરો',
        'tools_title': 'વધારાના સુરક્ષા સાધનો',
        'encode_decode': 'એન્કોડ/ડીકોડ: વેબ-સંબંધિત સમસ્યાઓના ડિબગીંગ માટે એન્કોડિંગ અને ડીકોડિંગ કાર્યો.',
        'encode': 'એન્કોડ',
        'decode': 'ડીકોડ',
        'live_timeline': 'લાઇવ ઇન્ટેલિજન્સ ટાઇમલાઇન',
        'search_placeholder': 'શોધ પરિમાણો...',
        'all_sources': 'બધા સ્ત્રોતો',
        'export_json': 'નિકાસ JSON',
        'timestamp': 'સમયરેખા',
        'level': 'સ્તર',
        'incident': 'ઘટના',
        'reasoning': 'તર્ક (AI)',
        'evidence': 'પુરાવો (લોગ લાઇન)',
        'mitigation': 'શમન',
        'no_logs': 'કોઈ લોગ સ્ત્રોતોનું વિશ્લેષણ કરવામાં આવ્યું નથી. તપાસ શરૂ કરવા માટે ફાઇલ અપલોડ કરો.',
        'faq': 'વારંવાર પુછાતા પ્રશ્નો',
        'login': 'લોગિન',
        'username': 'એક્સેસ આઈડી',
        'password': 'સુરક્ષા કી',
        'signin': 'સાઇન ઇન કરો',
        'no_account': 'એક્સેસ કી નથી?',
        'request_access': 'એક્સેસ માટે વિનંતી કરો',
        'already_have': 'શું તમારી પાસે પહેલેથી જ એક્સેસ આઈડી છે?',
        'create_account': 'ખાતું બનાવો',
        'change_lang': 'ભાષા',
        'english': 'English',
        'hindi': 'हिन्दी',
        'gujarati': 'ગુજરાતી',
        'kb_title': 'Knowledge Base',
        'kb_subtitle': 'Frequently Asked Questions & System Introduction',
        'faq1_q': 'What log formats are supported?',
        'faq1_a': 'Script auto-detects common formats (ISO 8601, Apache/Nginx, Syslog, JSON, etc.) to extract key fields.',
        'faq2_q': 'How does the log analysis work? Is my data sent anywhere?',
        'faq2_a': 'The analysis happens in two stages. First, a small sample of your logs (up to 50 lines) is sent to our server for a quick validation to determine the log structure and generate parsing rules. <br><br> Then, the full log data is processed entirely within your browser. Your complete log data never leaves your machine for the standard parsing and aggregation.',
        'faq3_q': 'What insights does the analysis provide?',
        'faq3_a': 'Get a dashboard view of log counts, errors, and anomalies. Explore trends with charts for time distribution, status codes, request paths, IPs, and response times.',
        'faq4_q': 'Are there log size limitations?',
        'faq4_a': 'No hard limit, but logs over 1MB trigger a warning. Since analysis runs in your browser, very large logs can impact performance depending on your machine.',
        'faq5_q': 'What if parsing fails for my logs?',
        'faq5_a': 'Auto-detection covers common formats well. If it struggles with your custom format, ensure key elements like timestamps are clear.',
        'contact_q': 'I have another question',
        'contact_a': 'Cool, contact us: ',
        'proceed_btn': 'Proceed to Dashboard',
        'troubleshoot_calendar': 'Calendar Troubleshooter',
        'troubleshoot_gmail': 'Troubleshoot Gmail',
        'troubleshoot_chrome': 'Chrome Connectivity',
        'flush_dns': 'Flush Public DNS',
        'troubleshoot_webrtc': 'WebRTC Troubleshooter',
        'system_feedback': 'System Feedback',
        'feedback_desc': 'Option only for owner (MV123 required to view)',
        'feedback_placeholder': 'Leave your feedback here...',
        'submit_feedback': 'Submit Feedback',
        'view_feedback_admin': 'View Feedback (Admin Only)'
    },
    'hi': {
        'title': 'थ्रेटनेट - इंटेलिजेंस डैशबोर्ड',
        'heading': 'थ्रेट',
        'subheading': 'नेट',
        'subtitle': 'कमांड इंटरफेस v1.2',
        'secured_session': 'सुरक्षित सत्र',
        'terminate': 'समाप्त करें',
        'total_signals': 'कुल सिग्नल',
        'telemetry': 'टेलीमेट्री अंतर्ग्रहण',
        'critical': 'गंभीर',
        'threats': 'प्रत्यक्ष प्रतिकूल खतरे',
        'suspicious': 'संदिग्ध',
        'anomalous': 'विषम व्यवहार पैटर्न',
        'system_info': 'सिस्टम जानकारी',
        'operational_log': 'परिचालन लॉग डेटा',
        'visualization': 'खतरा विज़ुअलाइज़ेशन बेसलाइन',
        'source_mgmt': 'खुफिया स्रोत प्रबंधन',
        'file_upload': 'फ़ाइल अपलोड',
        'paste_btn': 'कोड/टेक्स्ट पेस्ट',
        'file_source': 'फ़ाइल स्रोत',
        'log_signature': 'लॉग हस्ताक्षर',
        'analyze_btn': 'स्रोत का विश्लेषण करें',
        'paste_label': 'रॉ लॉग डेटा पेस्ट करें',
        'paste_placeholder': 'यहां लॉग लाइनें पेस्ट करें...',
        'ingest_btn': 'पेस्ट इनगेस्ट करें',
        'tools_title': 'अतिरिक्त सुरक्षा उपकरण',
        'encode_decode': 'एन्कोड/डिकोड: वेब-संबंधित समस्याओं के डिबगिंग के लिए एन्कोडिंग और डिकोडिंग फ़ंक्शन।',
        'encode': 'एन्कोड',
        'decode': 'डिकोड',
        'live_timeline': 'लाइव इंटेलिजेंस टाइमलाइन',
        'search_placeholder': 'खोज पैरामीटर...',
        'all_sources': 'सभी स्रोत',
        'export_json': 'निर्यात JSON',
        'timestamp': 'समय-सीमा',
        'level': 'स्तर',
        'incident': 'घटना',
        'reasoning': 'तर्क (AI)',
        'evidence': 'साक्ष्य (लॉग लाइन)',
        'mitigation': 'शमन',
        'no_logs': 'किसी लॉग स्रोत का विश्लेषण नहीं किया गया। पहचान शुरू करने के लिए एक फ़ाइल अपलोड करें।',
        'faq': 'सामान्य प्रश्न',
        'login': 'लॉगिन',
        'username': 'एक्सेस आईडी',
        'password': 'सुरक्षा कुंजी',
        'signin': 'साइन इन करें',
        'no_account': 'एक्सेस कुंजी नहीं है?',
        'request_access': 'एक्सेस का अनुरोध करें',
        'already_have': 'क्या आपके पास पहले से एक्सेस आईडी है?',
        'create_account': 'खाता बनाएं',
        'change_lang': 'भाषा',
        'english': 'English',
        'hindi': 'हिन्दी',
        'gujarati': 'ગુજરાતી',
        'kb_title': 'ज्ञानकोष',
        'kb_subtitle': 'अक्सर पूछे जाने वाले प्रश्न और सिस्टम परिचय',
        'faq1_q': 'कौन से लॉग प्रारूप समर्थित हैं?',
        'faq1_a': 'स्क्रिप्ट मुख्य फ़ील्ड निकालने के लिए सामान्य प्रारूपों (ISO 8601, Apache/Nginx, Syslog, JSON, आदि) का स्वतः पता लगाती है।',
        'faq2_q': 'लॉग विश्लेषण कैसे काम करता है? क्या मेरा डेटा कहीं भेजा जाता है?',
        'faq2_a': 'विश्लेषण दो चरणों में होता है। सबसे पहले, लॉग संरचना निर्धारित करने और पार्सिंग नियम उत्पन्न करने के लिए त्वरित सत्यापन के लिए आपके लॉग का एक छोटा सा नमूना (50 लाइनों तक) हमारे सर्वर पर भेजा जाता है। <br><br> फिर, पूर्ण लॉग डेटा पूरी तरह से आपके ब्राउज़र के भीतर संसाधित होता है। आपका पूरा लॉग डेटा मानक पार्सिंग और एकत्रीकरण के लिए आपकी मशीन से बाहर कभी नहीं जाता है।',
        'faq3_q': 'विश्लेषण क्या अंतर्दृष्टि प्रदान करता है?',
        'faq3_a': 'लॉग काउंट, त्रुटियों और विसंगतियों का डैशबोर्ड दृश्य प्राप्त करें। समय वितरण, स्थिति कोड, अनुरोध पथ, आईपी और प्रतिक्रिया समय के चार्ट के साथ प्रवृत्तियों का पता लगाएं।',
        'faq4_q': 'क्या लॉग आकार की सीमाएं हैं?',
        'faq4_a': 'कोई कठोर सीमा नहीं है, लेकिन 1MB से अधिक के लॉग चेतावनी ट्रिगर करते हैं। चूंकि विश्लेषण आपके ब्राउज़र में चलता है, इसलिए बहुत बड़े लॉग आपकी मशीन के आधार पर प्रदर्शन को प्रभावित कर सकते हैं।',
        'faq5_q': 'क्या होगा यदि मेरे लॉग के लिए पार्सिंग विफल हो जाए?',
        'faq5_a': 'ऑटो-डिटेक्शन सामान्य प्रारूपों को अच्छी तरह से कवर करता है। यदि यह आपके कस्टम प्रारूप के साथ संघर्ष करता है, तो सुनिश्चित करें कि टाइमस्टैम्प जैसे प्रमुख तत्व स्पष्ट हैं।',
        'contact_q': 'मेरे पास एक और प्रश्न है',
        'contact_a': 'बढ़िया, हमसे संपर्क करें: ',
        'proceed_btn': 'डैशबोर्ड पर आगे बढ़ें',
        'troubleshoot_calendar': 'कैलेंडर समस्यानिवारक',
        'troubleshoot_gmail': 'जीमेल समस्या निवारण',
        'troubleshoot_chrome': 'क्रोम कनेक्टिविटी',
        'flush_dns': 'सार्वजनिक डीएनएस फ्लश करें',
        'troubleshoot_webrtc': 'वेबआरटीसी समस्यानिवारक',
        'system_feedback': 'सिस्टम प्रतिक्रिया',
        'feedback_desc': 'विकल्प केवल स्वामी के लिए (देखने के लिए MV123 आवश्यक)',
        'feedback_placeholder': 'अपनी प्रतिक्रिया यहाँ छोड़ें...',
        'submit_feedback': 'प्रतिक्रिया भेजें',
        'view_feedback_admin': 'प्रतिक्रिया देखें (केवल व्यवस्थापक)'
    },
    'gu': {
        'title': 'થ્રેટનેટ - ઇન્ટેલિજન્સ ડેશબોર્ડ',
        'heading': 'થ્રેટ',
        'subheading': 'નેટ',
        'subtitle': 'કમાન્ડ ઈન્ટરફેસ v1.2',
        'secured_session': 'સુરક્ષિત સત્ર',
        'terminate': 'સમાપ્ત કરો',
        'total_signals': 'કુલ સિગ્નલ',
        'telemetry': 'ટેલીમેટ્રી ઇન્જેશન',
        'critical': 'ગંભીર',
        'threats': 'સીધા પ્રતિકૂળ જોખમો',
        'suspicious': 'શંકાસ્પદ',
        'anomalous': 'અસાધારણ વર્તણૂક પેટર્ન',
        'system_info': 'સિસ્ટમ માહિતી',
        'operational_log': 'ઓપરેશનલ લોગ ડેટા',
        'visualization': 'થ્રેટ વિઝ્યુલાઇઝેશન બેઝલાઇન',
        'source_mgmt': 'ઇન્ટેલિજન્સ સોર્સ મેનેજમેન્ટ',
        'file_upload': 'ફાઇલ અપલોડ',
        'paste_btn': 'કોડ/ટેક્સ્ટ પેસ્ટ',
        'file_source': 'ફાઇલ સ્ત્રોત',
        'log_signature': 'લોગ હસ્તાક્ષર',
        'analyze_btn': 'સ્ત્રોતનું વિશ્લેષણ કરો',
        'paste_label': 'કાચો લોગ ડેટા પેસ્ટ કરો',
        'paste_placeholder': 'અહીં લોગ લાઈનો પેસ્ટ કરો...',
        'ingest_btn': 'પેસ્ટ ઇન્જેસ્ટ કરો',
        'tools_title': 'વધારાના સુરક્ષા સાધનો',
        'encode_decode': 'એન્કોડ/ડીકોડ: વેબ-સંબંધિત સમસ્યાઓના ડિબગીંગ માટે એન્કોડિંગ અને ડીકોડિંગ કાર્યો.',
        'encode': 'એન્કોડ',
        'decode': 'ડીકોડ',
        'live_timeline': 'લાઇવ ઇન્ટેલિજન્સ ટાઇમલાઇન',
        'search_placeholder': 'શોધ પરિમાણો...',
        'all_sources': 'બધા સ્ત્રોતો',
        'export_json': 'નિકાસ JSON',
        'timestamp': 'સમયરેખા',
        'level': 'સ્તર',
        'incident': 'ઘટના',
        'reasoning': 'તર્ક (AI)',
        'evidence': 'પુરાવો (લોગ લાઇન)',
        'mitigation': 'શમન',
        'no_logs': 'કોઈ લોગ સ્ત્રોતોનું વિશ્લેષણ કરવામાં આવ્યું નથી. તપાસ શરૂ કરવા માટે ફાઇલ અપલોડ કરો.',
        'faq': 'વારંવાર પુછાતા પ્રશ્નો',
        'login': 'લોગિન',
        'username': 'એક્સેસ આઈડી',
        'password': 'સુરક્ષા કી',
        'signin': 'સાઇન ઇન કરો',
        'no_account': 'એક્સેસ કી નથી?',
        'request_access': 'એક્સેસ માટે વિનંતી કરો',
        'already_have': 'શું તમારી પાસે પહેલેથી જ એક્સેસ આઈડી છે?',
        'create_account': 'ખાતું બનાવો',
        'change_lang': 'ભાષા',
        'english': 'English',
        'hindi': 'हिन्दी',
        'gujarati': 'ગુજરાતી',
        'kb_title': 'નોલેજ બેઝ',
        'kb_subtitle': 'વારંવાર પૂછાતા પ્રશ્નો અને સિસ્ટમ પરિચય',
        'faq1_q': 'કયા લોગ ફોર્મેટ્સ સપોર્ટેડ છે?',
        'faq1_a': 'સ્ક્રિપ્ટ કી ફીલ્ડ્સ કાઢવા માટે સામાન્ય ફોર્મેટ્સ (ISO 8601, Apache/Nginx, Syslog, JSON, વગેરે) ને ઓટો-ડિટેક્ટ કરે છે.',
        'faq2_q': 'લોગ વિશ્લેષણ કેવી રીતે કામ કરે છે? શું મારો ડેટા ક્યાંય મોકલવામાં આવે છે?',
        'faq2_a': 'વિશ્લેષણ બે તબક્કામાં થાય છે. પ્રથમ, લોગ સ્ટ્રક્ચર નક્કી કરવા અને પાર્સિંગ નિયમો જનરેટ કરવા માટે તમારા લોગના નાના સેમ્પલ (50 લીટીઓ સુધી) ઝડપી માન્યતા માટે અમારા સર્વર પર મોકલવામાં આવે છે. <br><br> પછી, સંપૂર્ણ લોગ ડેટા સંપૂર્ણપણે તમારા બ્રાઉઝરમાં પ્રોસેસ થાય છે. તમારો સંપૂર્ણ લોગ ડેટા સ્ટાન્ડર્ડ પાર્સિંગ અને એકત્રીકરણ માટે તમારા મશીનથી બહાર ક્યારેય જતો નથી.',
        'faq3_q': 'વિશ્લેષણ કઈ આંતરદૃષ્ટિ પૂરી પાડે છે?',
        'faq3_a': 'લોગની ગણતરી, ભૂલો અને વિસંગતતાઓનું ડેશબોર્ડ વ્યુ મેળવો. સમય વિતરણ, સ્ટેટસ કોડ્સ, વિનંતી પાથ, IPs અને પ્રતિભાવ સમય માટેના ચાર્ટ સાથે ટ્રેન્ડ્સ શોધો.',
        'faq4_q': 'શું લોગ સાઈઝની મર્યાદાઓ છે?',
        'faq4_a': 'કોઈ સખત મર્યાદા નથી, પરંતુ 1MB થી વધુના લોગ ચેતવણી ટ્રિગર કરે છે. વિશ્લેષણ તમારા બ્રાઉઝરમાં ચાલતું હોવાથી, ખૂબ મોટા લોગ તમારા મશીનના આધારે કામગીરીને અસર કરી શકે છે.',
        'faq5_q': 'જો મારા લોગ માટેનું પાર્સિંગ નિષ્ફળ જાય તો?',
        'faq5_a': 'ઓટો-ડિટેક્શન સામાન્ય ફોર્મેટ્સને સારી રીતે આવરી લે છે. જો તે તમારા કસ્ટમ ફોર્મેટ સાથે સંઘર્ષ કરે છે, તો ખાતરી કરો કે ટાઇમસ્ટેમ્પ જેવા મુખ્ય તત્વો સ્પષ્ટ છે.',
        'contact_q': 'મારી પાસે બીજો પ્રશ્ન છે',
        'contact_a': 'સરસ, અમારો સંપર્ક કરો: ',
        'proceed_btn': 'ડેશબોર્ડ પર આગળ વધો',
        'troubleshoot_calendar': 'કેલેન્ડર મુશ્કેલીનિવારક',
        'troubleshoot_gmail': 'જીમેલ મુશ્કેલીનિવારણ',
        'troubleshoot_chrome': 'ક્રોમ કનેક્ટિવિટી',
        'flush_dns': 'જાહેર ડીએનએસ ફ્લશ કરો',
        'troubleshoot_webrtc': 'વેબઆરટીસી મુશ્કેલીનિવારક',
        'system_feedback': 'સિસ્ટમ પ્રતિસાદ',
        'feedback_desc': 'વિકલ્પ ફક્ત માલિક માટે (જોવા માટે MV123 જરૂરી)',
        'feedback_placeholder': 'તમારો પ્રતિસાદ અહીં મૂકો...',
        'submit_feedback': 'પ્રતિસાદ મોકલો',
        'view_feedback_admin': 'પ્રતિસાદ જુઓ (ફક્ત એડમિન માટે)'
    }
}

@app.context_processor
def inject_translations():
    lang = session.get('lang', 'en')
    def translate(key):
        return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, key)
    return dict(_t=translate, current_lang=lang)

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in TRANSLATIONS:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"[*] Login attempt: {username}")
        
        if username in USERS and USERS[username] == password:
            session['user'] = username
            flash(f'Session established for {username}', 'success')
            return redirect(url_for('faq')) # Redirect to FAQ after login
        else:
            flash('Invalid Access ID or Security Key', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS:
            flash('Access ID already exists', 'danger')
        else:
            USERS[username] = password
            flash('Account created! Sign in to access ThreatNet.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/faq')
def faq():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('faq.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Calculate stats
    stats = {
        'total': len(current_alerts),
        'critical': len([a for a in current_alerts if a['severity'] in ['CRITICAL', 'ERROR']]),
        'high': len([a for a in current_alerts if a['severity'] in ['HIGH', 'WARNING']]),
        'medium': len([a for a in current_alerts if a['severity'] in ['MEDIUM', 'INFO']]),
        'low': len([a for a in current_alerts if a['severity'] == 'LOW'])
    }
    
    return render_template('dashboard.html', alerts=current_alerts, stats=stats, history=session_history)

@app.route('/terminate')
def terminate_session():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    global current_alerts, session_history
    if current_alerts:
        session_history.append({
            'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'count': len(current_alerts)
        })
        current_alerts = []
    
    flash('ThreatNet session terminated. Previous analysis archived in history.', 'success')
    session.pop('user', None) # Log user out
    return redirect(url_for('login')) # Go to Login/Sign In page

@app.route('/analyze-combined', methods=['POST'])
def analyze_combined():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    file = request.files.get('file')
    log_content = request.form.get('log_content')
    log_type = request.form.get('log_type', 'linux_auth')
    
    content_to_scan = ""
    
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        with open(filepath, 'r') as f:
            content_to_scan += f.read() + "\n"
            
    if log_content and log_content.strip():
        content_to_scan += log_content + "\n"
        
    if not content_to_scan.strip():
        flash('No file uploaded or log text provided', 'danger')
        return redirect(url_for('dashboard'))
        
    new_alerts = engine.scan_log(content_to_scan, log_type)
    
    global current_alerts
    current_alerts = new_alerts + current_alerts
    
    flash(f'Scan complete! Detected {len(new_alerts)} incidents.', 'success')
    return redirect(url_for('dashboard'))

feedbacks = []

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'user' not in session:
        return redirect(url_for('login'))
    fb = request.form.get('feedback')
    if fb:
        feedbacks.append({'user': session['user'], 'content': fb, 'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
        flash('Feedback submitted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/view_feedback', methods=['GET', 'POST'])
def view_feedback():
    from flask import render_template_string
    if request.method == 'POST':
        if request.form.get('password') == 'MV123':
            session['feedback_unlocked'] = True
        else:
            flash('Invalid admin password', 'danger')
            
    if session.get('feedback_unlocked'):
        html = """
        <!DOCTYPE html><html><head><title>Admin Feedback</title>
        <style>body{background:#050b15;color:#fff;font-family:sans-serif;padding:2rem;} .card{background:#111827;padding:1rem;margin-bottom:1rem;border-radius:8px;}</style>
        </head><body>
        <h2>User Feedback (Admin Only)</h2>
        <a href="/dashboard" style="color:#00f3ff;">Back to Dashboard</a>
        <div style="margin-top:2rem;">
            {% for f in feedbacks %}
                <div class="card"><strong>{{ f.user }}</strong> ({{ f.date }})<p>{{ f.content }}</p></div>
            {% else %}
                <p>No feedback available yet.</p>
            {% endfor %}
        </div>
        </body></html>
        """
        return render_template_string(html, feedbacks=feedbacks)
        
    html = """
    <!DOCTYPE html><html><head><title>Admin Login</title>
    <style>body{background:#050b15;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;} .card{background:#111827;padding:2rem;border-radius:12px;text-align:center;}</style>
    </head><body>
    <div class="card">
        <h3>View Feedback</h3>
        <form method="POST">
            <input type="password" name="password" placeholder="Admin Password" required style="padding:0.5rem;border-radius:4px;"><br><br>
            <button type="submit" style="padding:0.5rem 1rem;background:#5e6ad2;color:#fff;border:none;border-radius:4px;">Unlock</button>
        </form>
    </div>
    </body></html>
    """
    return render_template_string(html)



@app.route('/export/<format>')
def export_data(format):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    filename = f"threatnet_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if format == 'json':
        engine.export_json(current_alerts, filepath)
    elif format == 'csv':
        engine.export_csv(current_alerts, filepath)
    else:
        flash('Invalid export format', 'danger')
        return redirect(url_for('dashboard'))
    
    return send_file(filepath, as_attachment=True)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Enabled ad-hoc SSL for HTTPS support as requested
    # Note: Requires 'pyopenssl' package (updated in requirements.txt)
    app.run(debug=True)