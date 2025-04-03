# Cohort Feedback: Security Assessment Task

## COMPONENT A: Security Report (25 marks)

### A1. Introduction (5 marks)

#### Performance Distribution
- **Extensive (5/5)**: 5% of cohort
- **Thorough (4/5)**: 15% of cohort
- **Sound (3/5)**: 30% of cohort
- **Basic (2/5)**: 50% of cohort

#### Strengths
- Higher-performing submissions provided comprehensive descriptions of the application's functionality and features
- Better reports clearly justified testing methodologies (black-box, white-box, grey-box)
- Strong introductions included well-defined scope statements outlining specific areas to be assessed
- Top submissions demonstrated clear connections between testing methods and broader security frameworks (e.g., OWASP)
- Some reports effectively used tables to map testing methodologies to specific vulnerability categories

#### Areas for Improvement
- 50% of submissions lacked sufficient detail about the application's architecture and functionality
- Many reports failed to justify why specific testing methodologies were chosen for particular vulnerability types
- Most introductions did not clearly demonstrate how planning and documentation methods underpinned the security approach
- Several reports provided overly generic scope statements without specific focus areas
- Many submissions lacked references to established security frameworks or standards

#### Quantifiable Assessment Criteria
1. **Application Description** (0-1 marks)
   - 0: No description or extremely vague mention of the application
   - 0.5: Basic identification of the application as a pizza ordering website
   - 1: Comprehensive description including user features, admin capabilities, and technical components

2. **Scope Definition** (0-1 marks)
   - 0: No defined scope
   - 0.5: General mention of security assessment areas
   - 1: Detailed scope with specific vulnerability categories and application components to be assessed

3. **Testing Methodology** (0-2 marks)
   - 0: No mention of testing methodologies
   - 0.5: Simple listing of methodologies without explanation
   - 1: Basic explanation of testing approaches
   - 1.5: Clear explanation with some justification for methodology choices
   - 2: Comprehensive explanation with specific justification for why each methodology was appropriate for different vulnerability types

4. **Planning Approach** (0-1 marks)
   - 0: No explanation of planning approach
   - 0.5: Basic mention of planning without details
   - 1: Clear demonstration of how planning and documentation methods supported the security assessment

### A2. Findings (10 marks)

#### Performance Distribution
- **Extensive (9-10/10)**: 10% of cohort
- **Thorough (7-8/10)**: 20% of cohort
- **Sound (5-6/10)**: 40% of cohort
- **Basic (3-4/10)**: 30% of cohort

#### Strengths
- Top submissions identified 10+ distinct vulnerabilities with comprehensive technical explanations
- Better reports included specific evidence with screenshots demonstrating exploitation
- Strong submissions provided detailed impact assessments for each vulnerability
- Higher-quality reports organised findings systematically with consistent structure
- Some reports effectively used OWASP references and categorisations

#### Areas for Improvement
- 70% of submissions provided generic vulnerability descriptions without specific evidence in the application
- Many reports lacked screenshots or code examples showing exploitation techniques
- Several submissions failed to assess the potential impacts of vulnerabilities
- Most reports did not include risk prioritisation or severity ratings
- Many submissions showed limited technical depth in vulnerability explanations

#### Quantifiable Assessment Criteria
1. **Vulnerability Identification** (0-3 marks)
   - 0: Fewer than 3 vulnerabilities identified
   - 1: 3-5 vulnerabilities identified
   - 2: 6-9 vulnerabilities identified
   - 3: 10+ vulnerabilities identified

2. **Technical Explanation** (0-3 marks)
   - 0: No technical explanation of vulnerabilities
   - 1: Basic descriptions without technical details
   - 2: Clear explanations with some technical details
   - 3: Comprehensive technical explanations demonstrating understanding of underlying security concepts

3. **Evidence and Demonstration** (0-2 marks)
   - 0: No evidence provided
   - 1: Limited evidence without clear demonstration
   - 2: Comprehensive evidence with screenshots and specific examples showing exploitation

4. **Impact Assessment** (0-2 marks)
   - 0: No impact assessment
   - 1: Basic mention of potential impacts without details
   - 2: Detailed assessment of potential impacts with specific consequences

### A3. Fixes (10 marks)

#### Performance Distribution
- **Extensive (9-10/10)**: 10% of cohort
- **Thorough (7-8/10)**: 20% of cohort
- **Sound (5-6/10)**: 20% of cohort
- **Basic (3-4/10)**: 50% of cohort

#### Strengths
- Top submissions provided clear before/after code comparisons for each vulnerability
- Better reports included explanations of security principles behind each fix
- Strong submissions demonstrated fixes with screenshots showing effectiveness
- Higher-quality reports addressed all identified vulnerabilities systematically
- Some reports organised fixes logically, grouping similar vulnerabilities

#### Areas for Improvement
- 50% of submissions provided incomplete fixes addressing only a subset of identified vulnerabilities
- Many reports lacked specific code examples or implementation details
- Several submissions showed heavy reliance on external sources without demonstrating personal understanding
- Most reports did not include evidence demonstrating the effectiveness of fixes
- Many submissions provided overly simplistic fixes without addressing root causes

#### Quantifiable Assessment Criteria
1. **Comprehensiveness** (0-3 marks)
   - 0: Fixes for fewer than 25% of identified vulnerabilities
   - 1: Fixes for 25-50% of identified vulnerabilities
   - 2: Fixes for 51-75% of identified vulnerabilities
   - 3: Fixes for 76-100% of identified vulnerabilities

2. **Technical Implementation** (0-3 marks)
   - 0: No specific implementation details
   - 1: Basic implementation suggestions without code examples
   - 2: Clear implementation with some code examples
   - 3: Comprehensive implementation with detailed code examples

3. **Security Principles** (0-2 marks)
   - 0: No explanation of security principles
   - 1: Basic mention of security concepts without detailed explanation
   - 2: Clear explanation of security principles behind each fix

4. **Verification and Evidence** (0-2 marks)
   - 0: No evidence of fix effectiveness
   - 1: Limited evidence without clear demonstration
   - 2: Comprehensive evidence with before/after comparisons demonstrating effectiveness

## Common Technical Inaccuracies

### 1. Vulnerability Classification Confusion

**Issue (60% of submissions)**: Inconsistent or incorrect classification of vulnerabilities according to OWASP standards.

**Example 1: IDOR vs. Broken Access Control**

Incorrect approach:
```markdown
## Identified Vulnerabilities
1. SQL Injection
2. Cross-Site Scripting
3. Broken Access Control
4. IDOR (Insecure Direct Object Reference)
```

Correct approach:
```markdown
## Identified Vulnerabilities
1. SQL Injection
2. Cross-Site Scripting
3. Broken Access Control
   - Insecure Direct Object Reference (IDOR)
   - Missing Function Level Access Control
```

**Example 2: Session Security Confusion**

Incorrect description:
```markdown
Session Fixation vulnerability was identified where an attacker could steal a user's session cookie and use it to access their account.
```

Correct description:
```markdown
Session Hijacking vulnerability was identified where an attacker could steal a user's session cookie and use it to access their account.

Session Fixation is a different vulnerability where an attacker sets a known session ID for a victim before they log in, allowing the attacker to use that same session ID to access the authenticated session.
```

### 2. SQL Injection Understanding

**Issue (40% of submissions)**: Lack of clear distinction between parameterised queries and string escaping, with insufficient explanation of why parameterisation is superior.

**Example of incorrect fix**:
```python
# Vulnerable code
query = f"SELECT * FROM users WHERE username = '{username}'"

# Incorrect fix (using string escaping)
username = username.replace("'", "\'")  # Escape single quotes
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**Example of correct fix with explanation**:
```python
# Vulnerable code
query = f"SELECT * FROM users WHERE username = '{username}'"

# Correct fix (using parameterised queries)
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

# Explanation: Parameterised queries separate the SQL code from the data,
# preventing the interpreter from treating user input as executable code.
# This is more secure than escaping because:
# 1. It handles all types of SQL injection, not just quote escaping
# 2. It's database-engine specific and properly handles different data types
# 3. It prevents second-order injection attacks
```

### 3. Security Header Implementation

**Issue (70% of submissions)**: Incomplete or ineffective security header recommendations.

**Example of incomplete implementation**:
```python
# Incomplete security header implementation
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

**Example of comprehensive implementation**:
```python
# Comprehensive security header implementation
@app.after_request
def add_security_headers(response):
    # Prevent clickjacking (both legacy and modern approaches)
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Content Security Policy (more flexible and powerful than X-Frame-Options)
    response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'"
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection in browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Use HTTPS only
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response
```

### 4. Testing Methodology Inconsistencies

**Issue (50% of submissions)**: Inconsistent application of testing methodologies.

**Example of inconsistent methodology**:
```markdown
## Testing Methodology
Black-box testing was used to identify vulnerabilities without knowledge of the internal code.

## SQL Injection Finding
By examining the source code in app.py, I found that the login function uses string concatenation for SQL queries:
```

**Example of consistent methodology**:
```markdown
## Testing Methodology
I used a combination of testing approaches:
- Black-box testing: Testing the application as a user without knowledge of code
- White-box testing: Code review to identify vulnerable patterns

## SQL Injection Finding
Initial black-box testing revealed potential SQL injection at the login endpoint.
Subsequent white-box code review confirmed this vulnerability in app.py:
```

### 5. Risk Assessment Limitations

**Issue (80% of submissions)**: Lack of formal risk assessment methodologies and quantitative metrics.

**Example of inadequate risk assessment**:
```markdown
SQL Injection is a serious vulnerability that could lead to data theft.
```

**Example of comprehensive risk assessment**:
```markdown
## SQL Injection in Login Function

**CVSS Score**: 8.6 (High)

**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L

**Impact Analysis**:
- Confidentiality: High - Attacker can access all database contents
- Integrity: Low - Attacker can modify some data but with limitations
- Availability: Low - Potential for database disruption but not complete denial of service

**Exploitation Likelihood**: High - Easily exploitable with common tools

**Remediation Priority**: Critical - Should be fixed immediately
```

## Overall Cohort Performance

### Score Distribution
- **Extensive (21-25/25)**: 10% of cohort
- **Thorough (16-20/25)**: 20% of cohort
- **Sound (11-15/25)**: 40% of cohort
- **Basic (0-10/25)**: 30% of cohort

### Key Differentiators Between Performance Bands

#### Extensive (21-25/25)
- Comprehensive identification of 10+ vulnerabilities with detailed technical explanations
- Systematic approach with consistent structure for findings and fixes
- Clear before/after code comparisons with evidence of fix effectiveness
- Strong understanding of security principles demonstrated throughout
- Appropriate references to security frameworks and standards
- Logical organisation with excellent documentation

#### Thorough (16-20/25)
- Identification of 7-10 vulnerabilities with good technical explanations
- Consistent approach to documenting findings and fixes
- Some before/after code comparisons with evidence
- Good understanding of security principles
- Some references to security frameworks
- Generally well-organised documentation

#### Sound (11-15/25)
- Identification of 5-7 vulnerabilities with basic technical explanations
- Inconsistent approach to documenting findings and fixes
- Limited before/after comparisons
- Basic understanding of security principles
- Few references to security frameworks
- Somewhat disorganised documentation

#### Basic (0-10/25)
- Identification of fewer than 5 vulnerabilities with minimal explanations
- Ad-hoc approach without consistent structure
- Very limited or no code examples for fixes
- Limited understanding of security principles
- No references to security frameworks
- Poorly organised documentation

## Recommendations for Future Improvement

1. **Introduction Enhancement**
   - Clearly describe the application's functionality and architecture
   - Explicitly define the scope of the security assessment
   - Justify testing methodologies with specific rationales
   - Connect testing approaches to established security frameworks
   - Demonstrate how planning underpins the security assessment

2. **Findings Improvement**
   - Provide specific evidence for each vulnerability with screenshots
   - Include code snippets showing vulnerable implementation
   - Assess potential impacts with specific consequences
   - Categorise vulnerabilities according to OWASP standards
   - Prioritise vulnerabilities using formal risk assessment

3. **Fixes Strengthening**
   - Address all identified vulnerabilities systematically
   - Provide clear before/after code comparisons
   - Explain security principles behind each fix
   - Demonstrate fix effectiveness with evidence
   - Consider implementation challenges and potential side effects

4. **Technical Understanding Development**
   - Develop deeper understanding of vulnerability classifications
   - Learn to distinguish between related security concepts
   - Understand the technical reasons behind security best practices
   - Practice implementing security controls in code
   - Study formal risk assessment methodologies

---

## Model Answers and Solutions

### COMPONENT A1: Introduction (5 marks)

#### Model Answer Elements

**Application Description**:

The Pizza Ordering Application is a Flask-based web application that allows users to browse and order pizzas, create user accounts and profiles, manage a shopping cart, and access administrative functions (for admin users). The application uses SQLite for data storage and includes various endpoints for user interaction, including user registration, authentication, profile management, password reset functionality, and file upload/download capabilities.

**Scope Definition**:

This security assessment covers the following areas:
- Authentication and session management
- Input validation and sanitisation
- Access control mechanisms
- Data storage and protection
- File handling and uploads
- Error handling and information disclosure
- API security
- Configuration settings
- Client-side security controls

**Testing Methodology**:

This assessment employs a combination of testing methodologies:

1. **White-box Testing**: Examining the source code directly to identify vulnerabilities such as SQL injection, hardcoded credentials, and insecure configurations. This approach is particularly effective for identifying issues in the application's backend logic and database interactions.

2. **Black-box Testing**: Testing the application as an end-user without knowledge of internal code, focusing on functionality and behaviour. This approach helps identify vulnerabilities from an attacker's perspective, such as broken access controls and client-side vulnerabilities.

3. **Grey-box Testing**: Combining elements of both approaches with partial knowledge of internal workings. This hybrid approach allows for targeted testing of specific components while maintaining an external perspective.

The choice of methodology for each vulnerability category is based on effectiveness and efficiency:
- SQL Injection: White-box testing to identify unparameterised queries in the codebase
- XSS Vulnerabilities: Black-box testing to identify input fields vulnerable to script injection
- Access Control: Grey-box testing to understand authentication mechanisms and test for bypasses
- File Upload Vulnerabilities: Black-box testing to attempt uploading malicious files
- Information Disclosure: Grey-box testing to identify sensitive data exposure points

**Planning Approach**:

The security assessment is underpinned by a structured approach following the OWASP Testing Guide methodology:
1. Information gathering and application mapping
2. Vulnerability identification using the OWASP Top 10 as a framework
3. Exploitation testing to confirm vulnerabilities
4. Impact assessment using CVSS scoring
5. Remediation planning with practical code examples

Documentation is maintained throughout the process, with findings categorised according to the OWASP Top 10 (2021) to ensure comprehensive coverage of modern web application security risks.

### COMPONENT A2: Findings (10 marks)

#### Model Answer Elements

**1. SQL Injection (A03:2021)**

*Vulnerability Description*:
Multiple instances of SQL injection vulnerabilities were identified throughout the application due to the use of unparameterised queries that directly incorporate user input into SQL statements.

*Evidence*:
```python
# Login function SQL injection
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
c.execute(query)

# Error test endpoint
@app.route("/error_test")
def error_test():
    username = request.args.get("username")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    c.execute(query)  
    return f"Executed query: {query}"
```

*Attack Vectors*:
- Authentication bypass: `username: admin' --` with any password
- Data extraction: `?username=admin' UNION SELECT * FROM users--`
- Database enumeration: `?username=' UNION SELECT name FROM sqlite_master WHERE type='table'--`

*Impact*:
Critical - Allows unauthorised access to any user account, including admin accounts, and potential extraction of all database data. An attacker could view, modify, or delete any information in the database.

*CVSS Score*: 9.8 (Critical)

**2. Broken Access Control (A01:2021)**

*Vulnerability Description*:
The application contains multiple broken access control vulnerabilities, including a debug endpoint that allows arbitrary file reading, an unrestricted file upload feature, and insecure direct object references (IDOR) in the profile view.

*Evidence*:
```python
# Debug endpoint
@app.route("/debug/<path:file_path>")
def debug_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    return content

# Unrestricted file upload
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["file"]
        file.save(f"./uploads/{file.filename}")
        return "File uploaded!"

# IDOR vulnerability
@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    # No authorization check
    # Direct access to any profile by ID
```

*Attack Vectors*:
- Source code access: `/debug/app.py`
- Database access: `/debug/users.db`
- Malicious file upload: Upload executable files (e.g., PHP shells)
- Profile enumeration: Sequentially access profiles by changing the user_id parameter

*Impact*:
Critical - Allows unauthorised access to sensitive files, source code, system information, and user data. Could lead to remote code execution through malicious file uploads.

*CVSS Score*: 9.1 (Critical)

**3. Security Misconfiguration (A05:2021)**

*Vulnerability Description*:
The application contains multiple security misconfigurations, including debug mode enabled in production, unrestricted CORS configuration, weak session configuration, missing security headers, and system information disclosure.

*Evidence*:
```python
# Debug mode enabled
app.run(debug=True)

# Unrestricted CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Weak session key
app.secret_key = "12345"

# System information disclosure
system_info = {
    'os': platform.system(),
    'version': platform.version(),
    'python': sys.version,
    'user': os.getlogin(),
    'cwd': os.getcwd(),
    'env': dict(os.environ)  # Exposes ALL environment variables!
}
```

*Attack Vectors*:
- Werkzeug debugger exploitation
- Cross-origin attacks through permissive CORS
- Session hijacking due to weak session configuration
- Clickjacking due to missing X-Frame-Options header
- API key theft from exposed environment variables

*Impact*:
Critical - Enables various attacks including remote code execution through the debugger, cross-origin attacks, session hijacking, and exposure of sensitive API keys.

*CVSS Score*: 8.6 (High)

**4. Cryptographic Failures (A02:2021)**

*Vulnerability Description*:
The application fails to properly protect sensitive data, storing passwords and credit card information in plaintext, using hardcoded credentials, and lacking encryption for sensitive data.

*Evidence*:
```python
# Plaintext password storage
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))

# Hardcoded credentials
DEFAULT_CREDENTIALS = {
    "admin": "admin123",  
    "test": "test123",    
    "demo": "demo123"     
}

# Plaintext sensitive data
return f"""
    <h2>User Profile</h2>
    <pre>
    Username: {data[0]}
    Full Name: {data[2]}
    Email: {data[3]}
    Phone: {data[4]}
    Credit Card: {data[5]}
    Address: {data[6]}
    </pre>
"""
```

*Attack Vectors*:
- Database access revealing all user passwords
- Source code access revealing hardcoded credentials
- Profile access revealing credit card information

*Impact*:
Critical - If the database is compromised, all user passwords and sensitive information are immediately exposed. Hardcoded credentials provide easy access to the application.

*CVSS Score*: 9.1 (Critical)

**5. Cross-Site Scripting (XSS) (A07:2021)**

*Vulnerability Description*:
The application is vulnerable to cross-site scripting due to unescaped user input in HTML responses and missing security headers.

*Evidence*:
```python
# Unescaped user input
return f"""
    <h2>User Profile</h2>
    <pre>
    Username: {data[0]}
    Full Name: {data[2]}
    Email: {data[3]}
    Phone: {data[4]}
    Credit Card: {data[5]}
    Address: {data[6]}
    </pre>
"""
```

*Attack Vectors*:
- Stored XSS: Insert malicious script in profile information
- Reflected XSS: Pass malicious script through URL parameters

*Impact*:
High - Allows execution of malicious scripts in users' browsers, potentially leading to session hijacking, credential theft, or malicious redirects.

*CVSS Score*: 8.2 (High)

**6. CORS Misconfiguration (A05:2021)**

*Vulnerability Description*:
The application implements a dangerously permissive CORS policy that allows requests from any origin to any endpoint.

*Evidence*:
```python
# Unrestricted CORS configuration
CORS(app, resources={r"/*": {"origins": "*"}})
```

*Attack Vectors*:
- Cross-origin data theft from authenticated endpoints
- API abuse from untrusted domains
- Session token exposure when combined with cookie vulnerabilities

*Impact*:
High - Enables cross-origin attacks and data theft when combined with other vulnerabilities. Particularly dangerous when combined with missing cookie security attributes.

*CVSS Score*: 7.5 (High)

**7. Insecure Cookie Configuration (A05:2021)**

*Vulnerability Description*:
The application uses cookies for session management but fails to set critical security attributes.

*Evidence*:
```python
# Missing secure cookie configuration
# No settings for:
# - SESSION_COOKIE_SECURE
# - SESSION_COOKIE_HTTPONLY
# - SESSION_COOKIE_SAMESITE
```

*Attack Vectors*:
- Session hijacking via JavaScript access to cookies
- Cookie theft over unencrypted connections
- Cross-site request forgery attacks
- Session fixation attacks

*Impact*:
Critical - Allows session theft and unauthorised actions, especially when combined with CORS misconfiguration.

*CVSS Score*: 8.0 (High)

**8. Clickjacking Vulnerability (A05:2021)**

*Vulnerability Description*:
The application is vulnerable to clickjacking (UI redressing) attacks due to missing security headers that would prevent framing.

*Evidence*:
```python
# Missing security headers:
# - X-Frame-Options
# - Content-Security-Policy (frame-ancestors directive)
```

*Attack Vectors*:
- UI redressing to trick users into clicking malicious elements
- Overlay attacks targeting login forms
- Credential theft through invisible frames
- Unintended actions on payment or admin pages

*Impact*:
High - Allows attackers to trick users into performing unintended actions, potentially leading to credential theft or unauthorised transactions.

*CVSS Score*: 6.5 (Medium)

**9. Path Traversal (A01:2021)**

*Vulnerability Description*:
The application contains multiple endpoints vulnerable to path traversal, allowing access to files outside the intended directory.

*Evidence*:
```python
# Download route with no path validation
@app.route("/download")
def download():
    filename = request.args.get("file")
    with open(filename, "r") as file:
        return file.read()

# Debug endpoint allows arbitrary file access
@app.route("/debug/<path:file_path>")
def debug_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    return content
```

*Attack Vectors*:
- Access to system files: `/download?file=../../../etc/passwd`
- Access to application source code: `/debug/../app.py`
- Access to configuration files: `/debug/../config/secrets.json`

*Impact*:
Critical - Allows reading arbitrary files on the server, potentially exposing sensitive system files, configuration data, and source code.

*CVSS Score*: 7.5 (High)

**10. Insecure Password Reset (A04:2021)**

*Vulnerability Description*:
The password reset functionality uses predictable tokens and lacks proper expiration and validation.

*Evidence*:
```python
# Predictable token generation
timestamp = int(time.time())
token = f"{username}_{timestamp}"

# Issues:
# - No token expiration
# - No rate limiting
# - Tokens stored in plaintext
```

*Attack Vectors*:
- Token prediction based on username and approximate timestamp
- Brute force attacks against token validation
- Unlimited password reset attempts

*Impact*:
High - Allows unauthorised password resets, potentially leading to account takeover.

*CVSS Score*: 7.0 (High)

**11. Verbose Error Messages (A04:2021)**

*Vulnerability Description*:
The application returns detailed error messages that expose sensitive information about the application structure and environment.

*Evidence*:
```python
@app.errorhandler(500)
def internal_error(error):
    import traceback
    error_details = {
        'error_type': str(type(error).__name__),
        'error_message': str(error),
        'stack_trace': traceback.format_exc(),
        'python_version': sys.version,
        'flask_version': flask.__version__,
        'debug_mode': app.debug,
        'database_path': 'users.db'
    }
    return f"""
        <h1>Internal Server Error</h1>
        <pre>
        Error Type: {error_details['error_type']}
        Message: {error_details['error_message']}
        
        Full Stack Trace:
        {error_details['stack_trace']}
        
        System Information:
        Python Version: {error_details['python_version']}
        Flask Version: {error_details['flask_version']}
        Debug Mode: {error_details['debug_mode']}
        Database: {error_details['database_path']}
        </pre>
    """, 500
```

*Attack Vectors*:
- Stack trace analysis to identify vulnerable components
- Database path discovery
- Application version fingerprinting for known vulnerabilities
- Code structure analysis

*Impact*:
Medium - Provides attackers with valuable information for crafting more targeted attacks.

*CVSS Score*: 5.5 (Medium)

**12. API Key Exposure (A02:2021)**

*Vulnerability Description*:
The application exposes sensitive API keys and credentials through the debug endpoint's system information disclosure.

*Evidence*:
```python
system_info = {
    'os': platform.system(),
    'version': platform.version(),
    'python': sys.version,
    'user': os.getlogin(),
    'cwd': os.getcwd(),
    'env': dict(os.environ)  # Exposes ALL environment variables!
}
```

*Attack Vectors*:
- Access to OpenAI API key: `sk-proj-DFyuAeor6jbuq8UNgZF4T3BlbkFJwsmtb6aBADXEgwCFq1SS`
- Access to other service credentials in environment variables
- Access to system user information

*Impact*:
Critical - Allows unauthorised use of paid API services, potential access to other systems, and financial impact from API abuse.

*CVSS Score*: 9.0 (Critical)

**13. Cross-Site Request Forgery (CSRF) (A05:2021)**

*Vulnerability Description*:
The application lacks CSRF protection on forms and state-changing operations.

*Evidence*:
```python
# No CSRF tokens in forms
<form method="POST" action="/change_password">
    <input type="password" name="new_password">
    <button type="submit">Change Password</button>
</form>

# No CSRF validation in route handlers
@app.route("/change_password", methods=["POST"])
def change_password():
    new_password = request.form.get("new_password")
    # Process password change without CSRF validation
```

*Attack Vectors*:
- Forged requests to change passwords
- Forged requests to modify cart contents
- Forged requests to perform admin actions

*Impact*:
High - Allows attackers to trick users into performing unintended actions while authenticated.

*CVSS Score*: 6.8 (Medium)

**14. Weak Session ID Generation (A02:2021)**

*Vulnerability Description*:
The application uses a weak secret key for session management, making session IDs predictable.

*Evidence*:
```python
# Weak secret key
app.secret_key = "12345"
```

*Attack Vectors*:
- Session prediction attacks
- Session fixation
- Session hijacking

*Impact*:
High - Allows attackers to guess or generate valid session IDs, potentially leading to unauthorised access.

*CVSS Score*: 7.5 (High)

**15. Hardcoded Credentials (A07:2021)**

*Vulnerability Description*:
The application contains hardcoded credentials in the source code.

*Evidence*:
```python
DEFAULT_CREDENTIALS = {
    "admin": "admin123",  
    "test": "test123",    
    "demo": "demo123"     
}
```

*Attack Vectors*:
- Direct authentication using known credentials
- Privilege escalation to admin account

*Impact*:
High - Provides immediate authenticated access to the application, including admin functionality.

*CVSS Score*: 7.8 (High)

### COMPONENT A3: Fixes (10 marks)

#### Model Answer Elements

**1. SQL Injection Remediation**

*Before*:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
c.execute(query)
```

*After*:
```python
# Use parameterised queries
c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))

# Alternative using SQLAlchemy ORM
user = User.query.filter_by(username=username, password=password).first()
```

*Explanation*:
Parameterised queries separate the SQL code from the data, preventing the interpreter from treating user input as executable code. This approach handles all types of SQL injection, not just quote escaping, and is database-engine specific to properly handle different data types.

**2. Broken Access Control Fixes**

*Before*:
```python
@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    # No authorization check
    # Fetch and display profile
```

*After*:
```python
# Authentication middleware
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    # Only allow users to view their own profile or admin to view any profile
    if int(session['user_id']) != user_id and session['role'] != 'admin':
        return "Access Denied", 403
    # Fetch and display profile
```

*Explanation*:
Implementing proper authentication and authorisation checks ensures that users can only access resources they are permitted to view. The login_required decorator enforces authentication, while the additional check ensures users can only view their own profiles unless they have admin privileges.

**3. Security Configuration Improvements**

*Before*:
```python
app.secret_key = "12345"
app.run(debug=True)
CORS(app, resources={r"/*": {"origins": "*"}})
```

*After*:
```python
# Secure session configuration
import os
from datetime import timedelta

app.secret_key = os.urandom(24)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

# Environment-specific debug mode
debug_mode = os.environ.get('FLASK_ENV') == 'development'
app.run(debug=debug_mode)

# Restricted CORS policy
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://trusted-domain.com"],
        "methods": ["GET", "POST"],
        "allow_credentials": True
    }
})

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

*Explanation*:
These changes implement multiple security best practices:
1. Using a strong, random secret key for sessions
2. Setting secure cookie attributes to prevent theft and misuse
3. Disabling debug mode in production environments
4. Implementing a restrictive CORS policy that only allows specific origins and methods
5. Adding security headers to prevent various client-side attacks

**4. Cryptographic Improvements**

*Before*:
```python
# Plaintext password storage
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
```

*After*:
```python
# Password hashing
from werkzeug.security import generate_password_hash, check_password_hash

# For registration:
password_hash = generate_password_hash(password)
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
          (username, password_hash))

# For login:
c.execute("SELECT * FROM users WHERE username = ?", (username,))
user = c.fetchone()
if user and check_password_hash(user[2], password):
    # Login successful

# For sensitive data
from cryptography.fernet import Fernet

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

# Store encrypted credit card
encrypted_cc = encrypt_data(credit_card, encryption_key)
c.execute("INSERT INTO profiles (user_id, credit_card) VALUES (?, ?)", 
          (user_id, encrypted_cc))
```

*Explanation*:
These changes implement proper cryptographic practices:
1. Using a secure hashing algorithm (bcrypt via Werkzeug) for password storage
2. Implementing encryption for sensitive data like credit card numbers
3. Separating the encryption key from the application code

**5. Secure File Handling**

*Before*:
```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["file"]
        file.save(f"./uploads/{file.filename}")
        return "File uploaded!"
```

*After*:
```python
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return 'File uploaded successfully'
        return 'File type not allowed', 400
    return render_template('upload.html')
```

*Explanation*:
These changes implement secure file handling practices:
1. Using secure_filename to sanitise filenames and prevent path traversal
2. Implementing file type validation to only allow safe file types
3. Setting a maximum file size to prevent denial of service attacks
4. Requiring authentication to upload files
5. Storing files in a designated directory with proper path joining
