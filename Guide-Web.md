# Web Security CTF Guide for Beginners

## What is Web Security in CTFs?

Web security challenges in CTF competitions involve exploiting vulnerabilities in web applications to find hidden flags. These challenges simulate real-world web security scenarios and test your ability to:

- Identify and exploit common web vulnerabilities
- Understand how web applications work (HTTP, cookies, sessions, etc.)
- Use browser developer tools and specialized web testing tools
- Manipulate web requests and responses
- Understand and exploit client-side and server-side code

Web challenges are often the most accessible category for beginners because they require minimal setup and use technologies most people are already familiar with.

## Key Terminology

- **HTTP/HTTPS**: Protocols used for web communication
- **Client-side**: Code executed in the user's browser (JavaScript, HTML, CSS)
- **Server-side**: Code executed on the web server (PHP, Python, Node.js, etc.)
- **Cookie**: Small piece of data stored in the browser
- **Session**: Server-side storage of user state
- **Same-Origin Policy**: Security mechanism restricting how documents from one origin interact with resources from another
- **DOM (Document Object Model)**: Programming interface for HTML/XML documents
- **AJAX**: Asynchronous JavaScript and XML for making requests without reloading the page
- **API**: Application Programming Interface for server communication
- **JWT (JSON Web Token)**: Compact, self-contained tokens for secure information transmission
- **CORS (Cross-Origin Resource Sharing)**: Mechanism for relaxing same-origin policy
- **CSP (Content Security Policy)**: Security layer to detect and mitigate certain attack types
- **WAF (Web Application Firewall)**: Filters to block malicious traffic

## Common Web CTF Challenge Types

### 1. **Client-Side Vulnerabilities**
- **XSS (Cross-Site Scripting)**
  - Injecting malicious scripts into websites viewed by others
  - Used to steal cookies, credentials, or perform actions on behalf of the victim

- **CSRF (Cross-Site Request Forgery)**
  - Forcing users to perform unwanted actions on sites they're authenticated to
  - Often combined with XSS or social engineering

- **DOM-Based Vulnerabilities**
  - Exploiting client-side JavaScript processing
  - Often involves manipulating URL parameters or form inputs

### 2. **Server-Side Vulnerabilities**

- **SQL Injection**
  - Inserting malicious SQL code into queries
  - Used to bypass authentication, extract data, or manipulate database

- **Command Injection**
  - Executing system commands through vulnerable inputs
  - Often found in features that interact with the operating system

- **Server-Side Request Forgery (SSRF)**
  - Making the server perform unintended requests
  - Used to access internal services or read local files

- **Directory Traversal/Path Traversal**
  - Accessing files outside intended directory
  - Often uses `../` sequences to navigate file system

- **File Inclusion Vulnerabilities**
  - Local File Inclusion (LFI): Including local files in the application
  - Remote File Inclusion (RFI): Including remote files in the application

### 3. **Authentication/Authorization Flaws**

- **Broken Authentication**
  - Weak credentials or session management
  - Password reset flaws, session fixation

- **Insecure Direct Object References (IDOR)**
  - Accessing resources by manipulating references
  - Often involves changing IDs in URLs or requests

- **JWT Vulnerabilities**
  - Weak signature verification
  - Insecure token handling

### 4. **Miscellaneous Web Challenges**

- **Web Cache Poisoning**
  - Exploiting caching mechanisms to serve malicious content

- **HTTP Request Smuggling**
  - Exploiting differences in request parsing between servers

- **Prototype Pollution**
  - Manipulating JavaScript object prototypes

- **Logic Flaws**
  - Exploiting application-specific business logic errors

## Essential Tools for Web Challenges

### Browser Tools

**1. Browser Developer Tools**
- Built-in tools for inspecting elements, network traffic, and JavaScript
- **When to use**: First tool to try for any web challenge

**2. Browser Extensions**
- Cookie Editor: Modify cookies directly
- FoxyProxy: Quick proxy switching
- Wappalyzer: Identify technologies used
- **When to use**: For specific manipulation tasks

### Proxies and Traffic Analysis

**1. Burp Suite (Community Edition)**
- Web proxy for intercepting and modifying traffic
- **When to use**: For intercepting, inspecting, and modifying HTTP(S) requests

**2. OWASP ZAP**
- Free alternative to Burp Suite
- **When to use**: When you need a full-featured free proxy

**3. Wireshark**
- Network packet analyzer
- **When to use**: For lower-level network analysis

### Reconnaissance Tools

**1. Gobuster/Dirb/Dirbuster**
- Directory brute forcing tools
- **When to use**: To discover hidden directories and files

**2. Nikto**
- Web server scanner
- **When to use**: For quick vulnerability scanning

**3. Sublist3r**
- Subdomain enumeration tool
- **When to use**: To discover subdomains

### Exploitation Frameworks

**1. SQLmap**
- Automated SQL injection tool
- **When to use**: When you've identified potential SQL injection points

**2. XSStrike**
- XSS detection and exploitation
- **When to use**: For testing and exploiting XSS vulnerabilities

**3. Commix**
- Command injection exploitation tool
- **When to use**: For testing command injection vulnerabilities

### Utilities

**1. CyberChef**
- Web-based data encoding/decoding/transformation
- **When to use**: For manipulating data formats

**2. JWT.io**
- Decode and manipulate JWT tokens
- **When to use**: For JWT-based challenges

**3. Postman/Insomnia**
- API testing tools
- **When to use**: For complex API interactions

**4. ngrok**
- Expose local servers to the internet
- **When to use**: For testing callbacks in XSS or SSRF

## Step-by-Step Approach to Web Challenges

1. **Reconnaissance**
   - Explore the website functionality
   - Check source code (HTML, JavaScript)
   - Look for comments or hidden elements
   - Review cookies and local storage
   - Identify technologies used

2. **Vulnerability Assessment**
   - Test input fields for injection vulnerabilities
   - Check URL parameters and form submissions
   - Review authentication mechanisms
   - Analyze request/response patterns

3. **Exploitation**
   - Use appropriate tools based on identified vulnerabilities
   - Modify requests as needed
   - Chain vulnerabilities if necessary
   - Escalate access if possible

4. **Flag Retrieval**
   - Look in exposed files or databases
   - Check admin sections or protected pages
   - Review source code for hidden flags
   - Extract from responses or error messages

## Practical Tips for Beginners

### General Tips

- **Always check the source code** first (Ctrl+U in most browsers)
- **Look for hidden HTML elements** (elements with `display: none` or `visibility: hidden`)
- **Check JavaScript files** for hardcoded values or interesting functions
- **Review robots.txt** for hidden directories
- **Look for patterns in URLs** and try changing parameters
- **Pay attention to error messages** - they often reveal useful information
- **Test different HTTP methods** (GET, POST, PUT, DELETE)
- **Try common usernames and passwords** for login forms

### XSS Tips

- **Test simple payloads first**: `<script>alert(1)</script>`
- **Try bypassing filters** with variations: `<img src=x onerror=alert(1)>`
- **Use event handlers** when script tags are filtered: `onload`, `onerror`, `onmouseover`
- **Check for reflected parameters** in the response

### SQL Injection Tips

- **Test basic payloads**: `' OR 1=1--`, `" OR 1=1--`
- **Look for error messages** that reveal database information
- **Use UNION attacks** to extract data from other tables
- **Try blind techniques** when no output is displayed

### File Inclusion Tips

- **Test with common files**: `/etc/passwd` (Linux), `C:\Windows\win.ini` (Windows)
- **Use PHP wrappers** for LFI: `php://filter/convert.base64-encode/resource=index.php`
- **Try null bytes** to bypass extensions: `file.php%00.jpg` (in older PHP versions)

### Authentication Tips

- **Check for default credentials**
- **Try username enumeration** based on error messages
- **Test password reset functionality** for vulnerabilities
- **Look for insecure session management**

## Common Payloads Cheat Sheet

### XSS Payloads
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

### SQL Injection Payloads
```
' OR 1=1--
" OR 1=1--
' UNION SELECT 1,2,3--
' UNION SELECT table_name,2,3 FROM information_schema.tables--
admin'--
```

### Command Injection Payloads
```
; ls
& whoami
| cat /etc/passwd
`id`
$(id)
```

### Directory Traversal Payloads
```
../../../etc/passwd
..\..\..\..\Windows\win.ini
/var/www/html/index.php
file:///etc/passwd
```

### SSRF Payloads
```
http://localhost/
http://127.0.0.1/
http://[::1]/
file:///etc/passwd
dict://internal-service:port/
```

## Practice Resources

- **Beginner-friendly platforms**:
  - PortSwigger Web Security Academy (free labs)
  - OWASP Juice Shop
  - WebGoat
  - PicoCTF (web challenges)
  - TryHackMe web rooms

- **Learning materials**:
  - OWASP Top 10
  - PortSwigger Web Security Academy learning materials
  - "Web Application Hacker's Handbook" by Dafydd Stuttard and Marcus Pinto
  - HackerSploit's web pentesting tutorials on YouTube

Remember that web security is a vast field, but many vulnerabilities follow common patterns. Start with the basics and gradually build your skills. Document your findings and techniques to create your own personal cheat sheet as you learn!
