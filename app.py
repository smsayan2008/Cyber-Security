import json
import os
import random
import string
import secrets
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from flask import Flask, render_template, request, redirect, url_for, jsonify
import pytz

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# DATA DIRECTORY
DATA_DIR = 'data'
HISTORY_FILE = os.path.join(DATA_DIR, 'history.json')
PASSWORDS_FILE = os.path.join(DATA_DIR, 'passwords.json')
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')

# India/West Bengal timezone
IST = pytz.timezone('Asia/Kolkata')

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# ============================================================================
# JINJA2 FILTERS
# ============================================================================

@app.template_filter('strftime')
def strftime_filter(value, fmt='%Y-%m-%d %H:%M:%S'):
    """Format datetime string."""
    if isinstance(value, str):
        if value == 'now':
            value = datetime.now()
        else:
            try:
                value = datetime.fromisoformat(value)
            except (ValueError, TypeError):
                return value
    if isinstance(value, datetime):
        return value.strftime(fmt)
    return value

@app.template_filter('strptime')
def strptime_filter(value, fmt='%Y-%m-%d %H:%M:%S'):
    """Parse datetime string."""
    if isinstance(value, datetime):
        return value
    try:
        return datetime.strptime(value, fmt)
    except (ValueError, TypeError):
        return value

# ============================================================================
# JSON MANAGEMENT
# ============================================================================

def load_json(filepath, default=None):
    """Load JSON file safely."""
    if default is None:
        default = {}
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except (json.JSONDecodeError, IOError):
        return default

def save_json(filepath, data):
    """Save JSON file safely."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except IOError as e:
        print(f"Error saving {filepath}: {e}")

# ============================================================================
# HISTORY MANAGEMENT
# ============================================================================

def add_to_history(activity_type, details):
    """Add an activity to history."""
    history = load_json(HISTORY_FILE, {'activities': []})
    if 'activities' not in history:
        history['activities'] = []
    
    activity = {
        'type': activity_type,
        'details': details,
        'timestamp': datetime.now().isoformat()
    }
    history['activities'].insert(0, activity)  # Insert at top (newest first)
    save_json(HISTORY_FILE, history)

def get_history(activity_type=None):
    """Get history, optionally filtered by type."""
    history = load_json(HISTORY_FILE, {'activities': []})
    activities = history.get('activities', [])
    
    if activity_type and activity_type != 'all':
        activities = [a for a in activities if a.get('type') == activity_type]
    
    return activities

def get_dashboard_stats():
    """Get statistics for dashboard."""
    history = load_json(HISTORY_FILE, {'activities': []})
    activities = history.get('activities', [])
    
    stats = {
        'passwords_generated': len([a for a in activities if a.get('type') == 'password_generated']),
        'passwords_checked': len([a for a in activities if a.get('type') == 'password_checked']),
        'links_checked': len([a for a in activities if a.get('type') == 'link_checked']),
        'warnings_found': len([a for a in activities if a.get('details', {}).get('risk_level') in ['MEDIUM RISK', 'HIGH RISK', 'CRITICAL RISK', 'DANGEROUS', '🔴 FRAUD / SCAM']]),
        'total_activities': len(activities)
    }
    return stats

def get_recent_activity(limit=5):
    """Get recent activities."""
    activities = get_history()
    return activities[:limit]

# ============================================================================
# PASSWORD GENERATION
# ============================================================================

def generate_humanreadable_password(name, dob, length, use_lower, use_upper, use_numbers, use_special):
    """Generate human-readable, memorable passwords based on name and DOB.
    
    Examples:
    - Sayan@2008
    - Tiger#1999
    - Name@YearOfBirth
    etc.
    """
    if length < 8 or length > 32:
        length = 14
    
    # Extract year from DOB if provided
    year_str = ""
    if dob:
        try:
            # Handle date format YYYY-MM-DD
            if isinstance(dob, str):
                year_str = dob.split('-')[0] if dob else ""
            else:
                year_str = str(dob.year) if hasattr(dob, 'year') else ""
        except:
            year_str = ""
    
    # Clean up name
    name_clean = ''.join(c for c in name if c.isalnum()) if name else "User"
    name_clean = name_clean[:10]  # Limit name length
    
    # Capitalize first letter
    if name_clean:
        name_clean = name_clean[0].upper() + name_clean[1:].lower()
    
    # Special characters to use
    special_chars = ['@', '#', '!']
    
    # Build passwords with variations
    passwords = []
    
    if use_special and year_str:
        # Format: Name@YYYY
        for special_char in special_chars:
            pwd = f"{name_clean}{special_char}{year_str}"
            if len(pwd) <= length:
                # Pad or truncate to exact length
                if len(pwd) < length:
                    # Add random numbers or letters to reach desired length
                    padding_needed = length - len(pwd)
                    for _ in range(padding_needed):
                        pwd += random.choice(string.digits)
                passwords.append(pwd[:length])
            else:
                # If too long, truncate
                passwords.append(pwd[:length])
    
    if use_special and year_str:
        # Format: Name@YYXX (last 2 digits of year + random)
        for special_char in ['@', '#']:
            year_suffix = year_str[-2:] if year_str else "00"
            pwd = f"{name_clean}{special_char}{year_suffix}"
            if len(pwd) < length:
                padding_needed = length - len(pwd)
                for _ in range(padding_needed):
                    pwd += random.choice(string.digits)
            passwords.append(pwd[:length])
    
    # Format: NameXXXX (name + random numbers)
    if use_numbers:
        pwd = name_clean
        padding_needed = length - len(pwd)
        if padding_needed > 0:
            pwd += ''.join(random.choice(string.digits) for _ in range(padding_needed))
        passwords.append(pwd[:length])
    
    # Format: Name + mixed content
    if use_special and use_numbers:
        special_char = random.choice(special_chars)
        pwd = f"{name_clean}{special_char}"
        padding_needed = length - len(pwd)
        if padding_needed > 0:
            pwd += ''.join(random.choice(string.digits) for _ in range(padding_needed))
        passwords.append(pwd[:length])
    
    # Fallback: generate additional passwords if we don't have enough variations
    while len(passwords) < 10:
        if use_special and year_str:
            pwd = f"{name_clean}{random.choice(special_chars)}{year_str}"
        elif use_numbers:
            pwd = name_clean + ''.join(random.choice(string.digits) for _ in range(length - len(name_clean)))
        else:
            pwd = name_clean
        
        if len(pwd) < length:
            if use_numbers:
                pwd += ''.join(random.choice(string.digits) for _ in range(length - len(pwd)))
            elif use_lower:
                pwd += ''.join(random.choice(string.ascii_lowercase) for _ in range(length - len(pwd)))
        
        pwd = pwd[:length]
        if pwd not in passwords:  # Avoid duplicates
            passwords.append(pwd)
    
    # Ensure we have exactly 10 unique passwords
    passwords = list(set(passwords))[:10]
    while len(passwords) < 10:
        # Generate completely random as fallback
        chars = ""
        if use_lower:
            chars += string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_numbers:
            chars += string.digits
        if use_special:
            chars += "!@#"
        
        if chars:
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            if pwd not in passwords:
                passwords.append(pwd)
    
    return passwords[:10]

def generate_password(length, use_lower, use_upper, use_numbers, use_special):
    """Generate a single password with specified options."""
    if length < 1 or length > 128:
        length = 14
    
    chars = ""
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_special:
        chars += "!@#"  # Small readable special character set
    
    if not chars:
        chars = string.ascii_lowercase
    
    password = ''.join(secrets.choice(chars) for _ in range(length))
    return password

def generate_improved_password(original_password):
    """Generate an improved password based on original password analysis.
    
    Maintains exact original length while improving security.
    """
    length = len(original_password)
    target_length = max(length, 12)  # Ensure at least 12 chars
    
    # Analyze original
    has_lower = any(c.islower() for c in original_password)
    has_upper = any(c.isupper() for c in original_password)
    has_number = any(c.isdigit() for c in original_password)
    has_special = any(c in "!@#$%^&*" for c in original_password)
    
    # Build improved password with better distribution
    improved = ""
    char_pool = ""
    
    if has_lower or not (has_upper or has_number or has_special):
        char_pool += string.ascii_lowercase
    if has_upper or not (has_lower or has_number or has_special):
        char_pool += string.ascii_uppercase
    if has_number or not (has_lower or has_upper or has_special):
        char_pool += string.digits
    if has_special or (not has_lower and not has_upper and not has_number):
        char_pool += "!@#$%^&*"
    
    # Ensure all character types are represented
    if has_lower and string.ascii_lowercase not in char_pool:
        char_pool += string.ascii_lowercase
    if has_upper and string.ascii_uppercase not in char_pool:
        char_pool += string.ascii_uppercase
    if has_number and string.digits not in char_pool:
        char_pool += string.digits
    if has_special and "!@#$%^&*" not in char_pool:
        char_pool += "!@#$%^&*"
    
    if not char_pool:
        char_pool = string.ascii_letters + string.digits
    
    # Generate password of exact length
    improved = ''.join(secrets.choice(char_pool) for _ in range(length))
    
    return improved

def analyze_password_strength(password):
    """Analyze password strength."""
    score = 0
    feedback = []
    
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_number = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/~`" for c in password)
    
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    
    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_number:
        score += 1
    if has_special:
        score += 1
    
    # Check for patterns
    has_repetition = len(set(password)) < len(password) * 0.6
    has_sequential = any(ord(password[i+1]) == ord(password[i]) + 1 for i in range(len(password)-1))
    
    if has_repetition:
        score = max(0, score - 1)
        feedback.append("Contains excessive repetition")
    if has_sequential:
        score = max(0, score - 1)
        feedback.append("Contains sequential characters")
    
    if score >= 4:
        strength = "Very Strong"
    elif score >= 3:
        strength = "Strong"
    elif score >= 2:
        strength = "Medium"
    else:
        strength = "Weak"
    
    return {
        'strength': strength,
        'score': score,
        'length': length,
        'has_lower': has_lower,
        'has_upper': has_upper,
        'has_number': has_number,
        'has_special': has_special,
        'feedback': feedback
    }

def detect_patterns(password):
    """Detect suspicious patterns in password."""
    patterns = []
    risks = []
    
    # Common patterns to check
    if any(pattern in password.lower() for pattern in ['password', 'pass', '123', 'abc', 'admin']):
        patterns.append("Common keywords detected")
        risks.append("HIGH RISK")
    
    # Repetition
    if len(set(password)) < len(password) * 0.5:
        patterns.append("Excessive character repetition")
        risks.append("MEDIUM RISK")
    
    # Sequential
    for i in range(len(password) - 2):
        if ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i+1]) + 1:
            patterns.append("Sequential characters found")
            risks.append("MEDIUM RISK")
            break
    
    return {
        'patterns': patterns,
        'risks': risks if risks else ["LOW RISK"]
    }

def analyze_password_risk(password):
    """Analyze password for security risks."""
    risks = []
    risk_factors = []
    
    if len(password) < 8:
        risks.append("SHORT_LENGTH")
        risk_factors.append("Password is too short (< 8 characters)")
    
    if len(password) < 12:
        risk_factors.append("Consider increasing to 12+ characters")
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_number = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/~`" for c in password)
    
    char_types = sum([has_upper, has_lower, has_number, has_special])
    if char_types < 3:
        risks.append("MISSING_CHAR_TYPES")
        risk_factors.append("Missing character types (uppercase, lowercase, numbers, special)")
    
    # Check repetition
    if len(set(password)) < len(password) * 0.6:
        risks.append("EXCESSIVE_REPETITION")
        risk_factors.append("Contains excessive character repetition")
    
    # Classify risk level
    if len(risks) >= 2:
        risk_level = "CRITICAL RISK"
    elif len(risks) == 1:
        risk_level = "HIGH RISK"
    elif char_types >= 3 and len(password) >= 12:
        risk_level = "LOW RISK"
    else:
        risk_level = "MEDIUM RISK"
    
    return {
        'risk_level': risk_level,
        'risk_factors': risk_factors,
        'strength_analysis': analyze_password_strength(password)
    }

# ============================================================================
# LINK ANALYSIS
# ============================================================================

def analyze_link(url):
    """Analyze URL for security risks."""
    indicators = []
    risk_level = "SAFEST"
    
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        
        # Check HTTPS
        if scheme != 'https':
            if scheme == 'http':
                indicators.append("Uses HTTP instead of HTTPS (unencrypted)")
                risk_level = "SUSPICIOUS"
            else:
                indicators.append("Unusual protocol")
        
        # Check for IP address
        if netloc.replace('.', '').isdigit():
            indicators.append("Direct IP address instead of domain name")
            risk_level = "SUSPICIOUS"
        
        # Check for @ symbol (phishing technique)
        if '@' in netloc:
            indicators.append("Contains @ symbol (possible phishing)")
            risk_level = "DANGEROUS"
        
        # Check for excessive subdomains
        subdomain_count = netloc.count('.')
        if subdomain_count > 4:
            indicators.append("Excessive subdomains")
            risk_level = "SUSPICIOUS"
        
        # Check URL length
        if len(url) > 100:
            indicators.append("Unusually long URL")
            risk_level = "SUSPICIOUS"
        
        # Check for suspicious characters
        suspicious_chars = ['%2e', '%3a', '%2f']  # Encoded ./:
        if any(char in url.lower() for char in suspicious_chars):
            indicators.append("Contains suspicious URL encoding")
            risk_level = "DANGEROUS"
        
        # Check for suspicious keywords in domain
        suspicious_keywords = ['verify', 'confirm', 'update', 'suspend', 'secure', 'paypal', 'amazon', 'apple', 'google']
        domain_parts = netloc.split('.')
        if any(keyword in domain_parts[0].lower() for keyword in suspicious_keywords):
            indicators.append("Domain contains suspicious keywords")
            risk_level = "SUSPICIOUS"
        
        # Check path for suspicious patterns
        if any(word in path.lower() for word in ['/login', '/verify', '/confirm', '/update']):
            indicators.append("Path contains suspicious patterns")
            if risk_level != "DANGEROUS":
                risk_level = "SUSPICIOUS"
        
        # If no indicators, it's safe
        if not indicators:
            risk_level = "SAFE"
        
    except Exception as e:
        indicators.append(f"Could not parse URL: {str(e)}")
        risk_level = "SUSPICIOUS"
    
    # Map risk level to emoji
    risk_emoji_map = {
        'SAFEST': '🟢',
        'SAFE': '🟢',
        'SUSPICIOUS': '🟡',
        'DANGEROUS': '🟠',
        'FRAUD': '🔴'
    }
    
    emoji = risk_emoji_map.get(risk_level.split()[0], '🟡')
    
    return {
        'url': url,
        'risk_level': f"{emoji} {risk_level}",
        'indicators': indicators,
        'recommendation': get_link_recommendation(risk_level)
    }

def get_link_recommendation(risk_level):
    """Get safety recommendation based on risk level."""
    if 'SAFEST' in risk_level or 'SAFE' in risk_level:
        return "This link appears safe based on structural analysis."
    elif 'SUSPICIOUS' in risk_level:
        return "Exercise caution. Verify the domain and do not enter sensitive information."
    else:  # DANGEROUS or FRAUD
        return "Avoid accessing this link. It shows strong indicators of malicious intent."

# ============================================================================
# SETTINGS
# ============================================================================

def get_settings():
    """Get application settings."""
    defaults = {
        'theme': 'dark',
        'password_length': '14',
        'use_lowercase': True,
        'use_uppercase': True,
        'use_numbers': True,
        'use_special': False,
        'password_visibility': 'masked',
        'language': 'en'
    }
    settings = load_json(SETTINGS_FILE, defaults)
    for key, value in defaults.items():
        if key not in settings:
            settings[key] = value
    return settings

def save_settings(settings):
    """Save application settings."""
    save_json(SETTINGS_FILE, settings)

# ============================================================================
# PROTECTED PASSWORD LIST
# ============================================================================

def get_password_list():
    """Get all stored passwords."""
    return load_json(PASSWORDS_FILE, {'passwords': []}).get('passwords', [])

def add_password_entry(service, username, password, notes=''):
    """Add a password entry."""
    data = load_json(PASSWORDS_FILE, {'passwords': []})
    if 'passwords' not in data:
        data['passwords'] = []
    
    entry = {
        'id': len(data['passwords']) + 1,
        'service': service,
        'username': username,
        'password': password,
        'notes': notes,
        'created_date': datetime.now().isoformat()
    }
    data['passwords'].append(entry)
    save_json(PASSWORDS_FILE, data)

def delete_password_entry(entry_id):
    """Delete a password entry."""
    data = load_json(PASSWORDS_FILE, {'passwords': []})
    data['passwords'] = [p for p in data['passwords'] if p.get('id') != entry_id]
    save_json(PASSWORDS_FILE, data)

# ============================================================================
# EDUCATION CONTENT
# ============================================================================

def get_education_content():
    """Get education content."""
    return {
        'en': {
            'title': 'Cybersecurity Guide',
            'categories': [
                {
                    'name': 'Password & Account Security',
                    'topics': [
                        {
                            'title': 'Password Security',
                            'what': 'Creating strong, unique passwords is your first line of defense against unauthorized access.',
                            'example': 'Using "MyPassword123" is weak, but "X7#kL9mQ$2nP" is strong.',
                            'why_risky': 'Weak passwords can be guessed or cracked using automated tools in seconds.',
                            'how_safe': [
                                'Use at least 12 characters',
                                'Mix uppercase, lowercase, numbers, and special characters',
                                'Avoid personal information (names, birthdays)',
                                'Avoid common words and patterns'
                            ],
                            'remember': 'A strong password is your shield against hackers.'
                        },
                        {
                            'title': 'Password Reuse',
                            'what': 'Using the same password across multiple websites.',
                            'example': 'Using "MyPass123" for email, social media, and banking.',
                            'why_risky': 'If one site is breached, attackers can access all your accounts.',
                            'how_safe': [
                                'Create unique passwords for each important account',
                                'Use a password generator to create strong unique passwords',
                                'Consider a local password manager'
                            ],
                            'remember': 'One breach, one password = One password. Don\'t reuse.'
                        },
                        {
                            'title': 'Multi-Factor Authentication (MFA)',
                            'what': 'Using two or more methods to verify your identity.',
                            'example': 'Password + OTP code, or password + fingerprint.',
                            'why_risky': 'Without MFA, a stolen password is all an attacker needs.',
                            'how_safe': [
                                'Enable MFA on all important accounts (email, banking, social)',
                                'Use authenticator apps instead of SMS when possible',
                                'Store backup codes in a safe place'
                            ],
                            'remember': 'MFA makes it exponentially harder for attackers to access your accounts.'
                        }
                    ]
                },
                {
                    'name': 'Web & Browsing Security',
                    'topics': [
                        {
                            'title': 'Phishing Attacks',
                            'what': 'Fraudulent emails or websites designed to trick you into revealing sensitive information.',
                            'example': 'An email claiming to be from your bank asking you to "verify your account" by clicking a link.',
                            'why_risky': 'You may unknowingly give attackers your passwords, credit card info, or personal details.',
                            'how_safe': [
                                'Never click links in unsolicited emails',
                                'Verify URLs by hovering (don\'t click) before opening',
                                'Check email addresses carefully - scammers use similar-looking addresses',
                                'Be suspicious of urgent requests for sensitive information'
                            ],
                            'remember': 'Banks never ask for passwords via email.'
                        },
                        {
                            'title': 'HTTPS vs HTTP',
                            'what': 'HTTPS encrypts data between your browser and a website. HTTP does not.',
                            'example': 'Entering credit card info on a non-HTTPS site = data sent in plain text.',
                            'why_risky': 'Unencrypted data can be intercepted and read by attackers on the same network.',
                            'how_safe': [
                                'Always look for the padlock icon in the address bar',
                                'URLs should start with https://',
                                'Never enter sensitive data on HTTP sites'
                            ],
                            'remember': 'HTTPS = Locked. HTTP = Open to the world.'
                        },
                        {
                            'title': 'Suspicious Links',
                            'what': 'URLs that appear legitimate but lead to malicious sites.',
                            'example': 'A link that says "https://amaz0n.com" instead of "https://amazon.com".',
                            'why_risky': 'Clicking can lead to phishing pages, malware downloads, or identity theft.',
                            'how_safe': [
                                'Verify URLs by hovering over links',
                                'Use link analysis tools like CyberShield\'s Link Checker',
                                'Go directly to official websites instead of clicking links',
                                'Be cautious with shortened URLs (bit.ly, tinyurl)'
                            ],
                            'remember': 'When in doubt, type the URL yourself.'
                        }
                    ]
                },
                {
                    'name': 'Social & Privacy',
                    'topics': [
                        {
                            'title': 'Social Engineering',
                            'what': 'Manipulating people into revealing confidential information or taking unsafe actions.',
                            'example': 'A scammer calling your company pretending to be IT support asking for your password.',
                            'why_risky': 'Can lead to immediate account compromise or malware installation.',
                            'how_safe': [
                                'Never give passwords or sensitive info over the phone or email',
                                'Verify identities through official channels',
                                'Be skeptical of unsolicited requests',
                                'Educate yourself on common social engineering tactics'
                            ],
                            'remember': 'Real support will never ask for your password.'
                        },
                        {
                            'title': 'Privacy & Personal Information',
                            'what': 'Protecting your personal data from being collected or misused.',
                            'example': 'Sharing your full birthdate, address, and phone number online.',
                            'why_risky': 'Can lead to identity theft, stalking, or targeted attacks.',
                            'how_safe': [
                                'Limit personal information on social media',
                                'Check privacy settings on all accounts',
                                'Don\'t share full birthdates, addresses, or phone numbers publicly',
                                'Be cautious with what information you provide online'
                            ],
                            'remember': 'Your personal information is valuable to attackers.'
                        }
                    ]
                },
                {
                    'name': 'Device & Data Protection',
                    'topics': [
                        {
                            'title': 'Device Security',
                            'what': 'Protecting your computer or phone from unauthorized access.',
                            'example': 'Using a strong login password and enabling device encryption.',
                            'why_risky': 'Without device security, anyone with physical access can steal all your data.',
                            'how_safe': [
                                'Use a strong password for your device login',
                                'Enable screen lock/automatic lock',
                                'Enable full disk encryption (BitLocker, FileVault)',
                                'Keep device in physical control'
                            ],
                            'remember': 'Your device is a gateway to all your online accounts.'
                        },
                        {
                            'title': 'Software Updates',
                            'what': 'Applying patches and updates to your operating system and applications.',
                            'example': 'Installing Windows or macOS updates, updating your browser.',
                            'why_risky': 'Unpatched software has known vulnerabilities attackers can exploit.',
                            'how_safe': [
                                'Enable automatic updates for your operating system',
                                'Update applications regularly',
                                'Use current versions of browsers and plugins',
                                'Don\'t delay or ignore update notifications'
                            ],
                            'remember': 'Updates patch security holes. Don\'t ignore them.'
                        },
                        {
                            'title': 'Backup & Data Protection',
                            'what': 'Keeping copies of your important data in case of loss or ransomware.',
                            'example': 'Using cloud backup (with strong passwords) or external hard drives.',
                            'why_risky': 'Without backups, ransomware or device failure means permanent data loss.',
                            'how_safe': [
                                'Create regular backups of important files',
                                'Use 3-2-1 backup rule: 3 copies, 2 different media, 1 offsite',
                                'Test your backups to ensure they work',
                                'Keep backup devices disconnected except during backup'
                            ],
                            'remember': 'Backups are your insurance policy against data loss.'
                        }
                    ]
                }
            ]
        },
        'bn': {
            'title': 'সাইবার নিরাপত্তা গাইড',
            'categories': [
                {
                    'name': 'পাসওয়ার্ড এবং অ্যাকাউন্ট সুরক্ষা',
                    'topics': [
                        {
                            'title': 'পাসওয়ার্ড সুরক্ষা',
                            'what': 'শক্তিশালী, অনন্য পাসওয়ার্ড তৈরি করা আপনার প্রথম প্রতিরক্ষা লাইন।',
                            'example': '"MyPassword123" দুর্বল, কিন্তু "X7#kL9mQ$2nP" শক্তিশালী।',
                            'why_risky': 'দুর্বল পাসওয়ার্ড সেকেন্ডের মধ্যে অনুমান বা ক্র্যাক করা যায়।',
                            'how_safe': [
                                'কমপক্ষে ১২ অক্ষর ব্যবহার করুন',
                                'বড় অক্ষর, ছোট অক্ষর, সংখ্যা এবং বিশেষ অক্ষর মিশান',
                                'ব্যক্তিগত তথ্য (নাম, জন্মতারিখ) এড়িয়ে চলুন',
                                'সাধারণ শব্দ এবং প্যাটার্ন এড়িয়ে চলুন'
                            ],
                            'remember': 'একটি শক্তিশালী পাসওয়ার্ড হ্যাকারদের বিরুদ্ধে আপনার ঢাল।'
                        },
                        {
                            'title': 'পাসওয়ার্ড পুনঃব্যবহার',
                            'what': 'একই পাসওয়ার্ড একাধিক ওয়েবসাইটে ব্যবহার করা।',
                            'example': 'সব জায়গায় "MyPass123" ব্যবহার করা - ইমেইল, সোশ্যাল মিডিয়া, ব্যাংকিং।',
                            'why_risky': 'একটি সাইট ভেঙে গেলে, আক্রমণকারীরা সব অ্যাকাউন্ট অ্যাক্সেস করতে পারবে।',
                            'how_safe': [
                                'প্রতিটি গুরুত্বপূর্ণ অ্যাকাউন্টের জন্য অনন্য পাসওয়ার্ড তৈরি করুন',
                                'পাসওয়ার্ড জেনারেটর ব্যবহার করে শক্তিশালী অনন্য পাসওয়ার্ড তৈরি করুন',
                                'একটি স্থানীয় পাসওয়ার্ড ম্যানেজার বিবেচনা করুন'
                            ],
                            'remember': 'প্রতিটি গুরুত্বপূর্ণ অ্যাকাউন্টের জন্য অনন্য পাসওয়ার্ড ব্যবহার করুন।'
                        },
                        {
                            'title': 'দুই-ফ্যাক্টর প্রমাণীকরণ (২FA)',
                            'what': 'আপনার পরিচয় যাচাই করতে দুই বা তার বেশি পদ্ধতি ব্যবহার করা।',
                            'example': 'পাসওয়ার্ড + OTP কোড, বা পাসওয়ার্ড + আঙুলের ছাপ।',
                            'why_risky': '২FA ছাড়া, একটি চোরা পাসওয়ার্ডই আক্রমণকারীর জন্য যথেষ্ট।',
                            'how_safe': [
                                'সব গুরুত্বপূর্ণ অ্যাকাউন্টে ২FA সক্ষম করুন',
                                'সম্ভব হলে SMS-এর পরিবর্তে অথেন্টিকেটর অ্যাপ ব্যবহার করুন',
                                'ব্যাকআপ কোড নিরাপদ জায়গায় সংরক্ষণ করুন'
                            ],
                            'remember': '২FA আক্রমণকারীদের জন্য প্রবেশাধিকার পাওয়া অনেক কঠিন করে।'
                        }
                    ]
                },
                {
                    'name': 'ওয়েব এবং ব্রাউজিং সুরক্ষা',
                    'topics': [
                        {
                            'title': 'ফিশিং আক্রমণ',
                            'what': 'জালিয়াতিপূর্ণ ইমেইল বা ওয়েবসাইট যা আপনাকে সংবেদনশীল তথ্য প্রকাশ করতে বিশ্বাস করায়।',
                            'example': 'আপনার ব্যাংক থেকে একটি ইমেইল যা আপনাকে "অ্যাকাউন্ট যাচাই" করতে একটি লিঙ্ক ক্লিক করতে বলে।',
                            'why_risky': 'আপনি অনিচ্ছাকৃতভাবে আক্রমণকারীদের পাসওয়ার্ড বা ক্রেডিট কার্ড তথ্য দিতে পারেন।',
                            'how_safe': [
                                'অনাবশ্যক ইমেইলের লিঙ্ক কখনও ক্লিক করবেন না',
                                'লিঙ্ক খোলার আগে URL যাচাই করুন (ক্লিক করবেন না)',
                                'ইমেইল ঠিকানা সাবধানে পরীক্ষা করুন - স্কাম্ররা একই রকম ঠিকানা ব্যবহার করে',
                                'সংবেদনশীল তথ্যের জরুরি অনুরোধে সন্দেহ করুন'
                            ],
                            'remember': 'ব্যাংক কখনও ইমেইলের মাধ্যমে পাসওয়ার্ড চায় না।'
                        },
                        {
                            'title': 'HTTPS বনাম HTTP',
                            'what': 'HTTPS আপনার ব্রাউজার এবং ওয়েবসাইটের মধ্যে ডেটা এনক্রিপ্ট করে। HTTP করে না।',
                            'example': 'অ-HTTPS সাইটে ক্রেডিট কার্ড তথ্য প্রবেশ = ডেটা খোলা পাঠানো।',
                            'why_risky': 'এনক্রিপ্ট করা ডেটা একই নেটওয়ার্কে আক্রমণকারীদের দ্বারা বাধা এবং পড়া যেতে পারে।',
                            'how_safe': [
                                'ঠিকানা বারে প্যাডলক আইকন খুঁজুন',
                                'URL https:// দিয়ে শুরু হওয়া উচিত',
                                'HTTP সাইটে সংবেদনশীল তথ্য প্রবেশ করবেন না'
                            ],
                            'remember': 'HTTPS = সুরক্ষিত। HTTP = বিশ্বের কাছে খোলা।'
                        }
                    ]
                }
            ]
        }
    }

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def dashboard():
    """Dashboard page."""
    stats = get_dashboard_stats()
    recent_activity = get_recent_activity(5)
    settings = get_settings()
    
    # Get current time in IST
    current_time_ist = datetime.now(IST)
    current_date = current_time_ist.strftime('%A, %B %d, %Y')
    current_clock = current_time_ist.strftime('%H:%M:%S')
    
    return render_template('dashboard.html', 
                         stats=stats,
                         recent_activity=recent_activity,
                         settings=settings,
                         current_date=current_date,
                         current_clock=current_clock)

@app.route('/password-generator', methods=['GET', 'POST'])
def password_generator():
    """Password generator page."""
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            dob = request.form.get('dob', '')
            
            # Validate and sanitize length
            try:
                length = int(request.form.get('length', 14))
            except (ValueError, TypeError):
                length = 14
            
            # Enforce valid range
            if length < 8:
                length = 8
            elif length > 32:
                length = 32
            
            use_lower = request.form.get('use_lower') == 'on'
            use_upper = request.form.get('use_upper') == 'on'
            use_numbers = request.form.get('use_numbers') == 'on'
            use_special = request.form.get('use_special') == 'on'
            
            # Ensure at least one character type is selected
            if not any([use_lower, use_upper, use_numbers, use_special]):
                use_lower = True
                use_upper = True
                use_numbers = True
            
            # Generate passwords using human-readable method if name is provided
            if name and name.strip():
                pwd_list = generate_humanreadable_password(name, dob, length, use_lower, use_upper, use_numbers, use_special)
                passwords = []
                for pwd in pwd_list:
                    # Ensure correct length
                    if len(pwd) != length:
                        pwd = pwd[:length] if len(pwd) > length else (pwd + random.choice(string.ascii_lowercase) * (length - len(pwd)))
                    strength = analyze_password_strength(pwd)['strength']
                    passwords.append({
                        'password': pwd,
                        'strength': strength
                    })
            else:
                # Fallback to random passwords if no name provided
                passwords = []
                for _ in range(10):
                    pwd = generate_password(length, use_lower, use_upper, use_numbers, use_special)
                    # Verify password is correct length
                    if len(pwd) != length:
                        pwd = pwd[:length] if len(pwd) > length else (pwd + 'a' * (length - len(pwd)))
                    strength = analyze_password_strength(pwd)['strength']
                    passwords.append({
                        'password': pwd,
                        'strength': strength
                    })
            
            # Save to history
            add_to_history('password_generated', {
                'count': 10,
                'length': length,
                'options': {
                    'lowercase': use_lower,
                    'uppercase': use_upper,
                    'numbers': use_numbers,
                    'special': use_special
                }
            })
            
            # Save settings
            settings = get_settings()
            settings['password_length'] = str(length)
            settings['use_lowercase'] = use_lower
            settings['use_uppercase'] = use_upper
            settings['use_numbers'] = use_numbers
            settings['use_special'] = use_special
            save_settings(settings)
            
            return render_template('password_generator.html', 
                                 passwords=passwords,
                                 form_submitted=True,
                                 settings=settings,
                                 generated_length=length)
        except Exception as e:
            return render_template('password_generator.html', error=str(e))
    
    settings = get_settings()
    return render_template('password_generator.html', settings=settings)

@app.route('/password-checker', methods=['GET', 'POST'])
def password_checker():
    """Password strength checker."""
    show_password = False
    password = ""
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        action = request.form.get('action', 'check')
        
        # Handle password visibility toggle
        if action == 'toggle_visibility':
            show_password = not request.form.get('show_password', '') == 'true'
            return render_template('password_checker.html', 
                                 show_password=show_password, 
                                 password=password)
        
        # Validate password input
        if not password:
            return render_template('password_checker.html', 
                                 error='Please enter a password', 
                                 show_password=False)
        
        if len(password) < 1 or len(password) > 128:
            return render_template('password_checker.html', 
                                 error='Password length must be between 1 and 128 characters', 
                                 show_password=show_password, 
                                 password=password)
        
        analysis = analyze_password_strength(password)
        
        # Generate 5 improved passwords of the EXACT same length
        improved = []
        for _ in range(5):
            pwd = generate_improved_password(password)
            # Ensure exact length
            if len(pwd) != len(password):
                pwd = pwd[:len(password)] if len(pwd) > len(password) else pwd.ljust(len(password), 'a')
            strength = analyze_password_strength(pwd)['strength']
            improved.append({
                'password': pwd,
                'strength': strength
            })
        
        # Save to history (don't store password, just metadata)
        add_to_history('password_checked', {
            'strength': analysis['strength'],
            'length': analysis['length']
        })
        
        return render_template('password_checker.html',
                             analysis=analysis,
                             improved=improved,
                             form_submitted=True,
                             show_password=show_password,
                             password=password)
    
    return render_template('password_checker.html', show_password=False)

@app.route('/pattern-analyzer', methods=['GET', 'POST'])
def pattern_analyzer():
    """Pattern analyzer."""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if not password:
            return render_template('pattern_analyzer.html', error='Please enter a password')
        
        analysis = detect_patterns(password)
        strength = analyze_password_strength(password)
        
        # Save to history
        add_to_history('pattern_analyzed', {
            'patterns': analysis['patterns'],
            'risks': analysis['risks']
        })
        
        return render_template('pattern_analyzer.html',
                             analysis=analysis,
                             strength=strength,
                             form_submitted=True,
                             password=password)
    
    return render_template('pattern_analyzer.html')

@app.route('/risk-analyzer', methods=['GET', 'POST'])
def risk_analyzer():
    """Risk analyzer."""
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        if not password:
            return render_template('risk_analyzer.html', error='Please enter a password')
        
        analysis = analyze_password_risk(password)
        
        # Save to history
        add_to_history('risk_analyzed', {
            'risk_level': analysis['risk_level'],
            'risk_factors': analysis['risk_factors']
        })
        
        return render_template('risk_analyzer.html',
                             analysis=analysis,
                             form_submitted=True)
    
    return render_template('risk_analyzer.html')

@app.route('/regenerator', methods=['GET', 'POST'])
def regenerator():
    """Regenerate with same settings."""
    if request.method == 'POST':
        length = int(request.form.get('length', 14))
        use_lower = request.form.get('use_lower') == 'on'
        use_upper = request.form.get('use_upper') == 'on'
        use_numbers = request.form.get('use_numbers') == 'on'
        use_special = request.form.get('use_special') == 'on'
        
        # Generate 10 passwords
        passwords = []
        for _ in range(10):
            pwd = generate_password(length, use_lower, use_upper, use_numbers, use_special)
            strength = analyze_password_strength(pwd)['strength']
            passwords.append({
                'password': pwd,
                'strength': strength
            })
        
        # Save to history
        add_to_history('password_regenerated', {
            'count': 10,
            'length': length
        })
        
        return render_template('regenerator.html',
                             passwords=passwords,
                             form_submitted=True,
                             length=length,
                             use_lower=use_lower,
                             use_upper=use_upper,
                             use_numbers=use_numbers,
                             use_special=use_special)
    
    settings = get_settings()
    return render_template('regenerator.html', settings=settings)

@app.route('/link-checker', methods=['GET', 'POST'])
def link_checker():
    """Link safety checker."""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        
        if not url:
            return render_template('link_checker.html', error='Please enter a URL')
        
        # Add protocol if missing
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        
        analysis = analyze_link(url)
        
        # Save to history
        add_to_history('link_checked', {
            'url': url,
            'risk_level': analysis['risk_level'],
            'indicators': analysis['indicators']
        })
        
        return render_template('link_checker.html',
                             analysis=analysis,
                             form_submitted=True)
    
    return render_template('link_checker.html')

@app.route('/cyberguard')
def cyberguard():
    """CyberGuard page."""
    stats = get_dashboard_stats()
    recent_activity = get_recent_activity(3)
    
    return render_template('cyberguard.html',
                         stats=stats,
                         recent_activity=recent_activity)

@app.route('/history')
def history():
    """History page."""
    activity_type = request.args.get('type', 'all')
    activities = get_history(activity_type if activity_type != 'all' else None)
    
    return render_template('history.html',
                         activities=activities,
                         activity_type=activity_type)

@app.route('/history/delete/<int:index>', methods=['POST'])
def delete_history(index):
    """Delete a history entry."""
    history = load_json(HISTORY_FILE, {'activities': []})
    if 'activities' in history and 0 <= index < len(history['activities']):
        history['activities'].pop(index)
        save_json(HISTORY_FILE, history)
    return redirect(url_for('history'))

@app.route('/history/confirm-delete/<int:index>')
def confirm_delete_history(index):
    """Confirm deletion of history entry."""
    history = load_json(HISTORY_FILE, {'activities': []})
    if 'activities' not in history or not (0 <= index < len(history['activities'])):
        return redirect(url_for('history'))
    
    activity = history['activities'][index]
    return render_template('confirm_delete_history.html', index=index, activity=activity)

@app.route('/history/clear', methods=['POST'])
def clear_history():
    """Clear all history."""
    save_json(HISTORY_FILE, {'activities': []})
    return redirect(url_for('history'))

@app.route('/history/confirm-clear')
def confirm_clear_history():
    """Confirm clearing all history."""
    history = load_json(HISTORY_FILE, {'activities': []})
    count = len(history.get('activities', []))
    return render_template('confirm_clear_history.html', count=count)

# ============================================================================
# APP ENTRY POINT
# ============================================================================

@app.route('/password-list', methods=['GET', 'POST'])
def password_list():
    """Password list page."""
    if request.method == 'POST':
        service = request.form.get('service', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        notes = request.form.get('notes', '').strip()
        
        if service and username and password:
            add_password_entry(service, username, password, notes)
            return redirect(url_for('password_list'))
    
    passwords = get_password_list()
    return render_template('password_list.html', passwords=passwords)

@app.route('/password-list/delete/<int:entry_id>', methods=['POST'])
def delete_password(entry_id):
    """Delete a password entry."""
    delete_password_entry(entry_id)
    return redirect(url_for('password_list'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Settings page."""
    if request.method == 'POST':
        current_settings = get_settings()
        current_settings['theme'] = request.form.get('theme', 'dark')
        current_settings['password_visibility'] = request.form.get('password_visibility', 'masked')
        current_settings['language'] = request.form.get('language', 'en')
        save_settings(current_settings)
        return redirect(url_for('settings'))
    
    current_settings = get_settings()
    return render_template('settings.html', settings=current_settings)

@app.route('/education')
def education():
    """Cybersecurity education guide."""
    lang = request.args.get('lang', 'en')
    if lang not in ['en', 'bn']:
        lang = 'en'
    
    content = get_education_content()[lang]
    return render_template('education.html', content=content, language=lang)

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)
