# Module 5: Assignment - OWASP Top 10 Code Fix:

This document includes:
Vulnerable code sample.  Why it’s vulnerable. Corrected/Secure versiono of code. Why the fix works. Official OWASP references

---

## 1 — Broken Access Control 

### Vulnerable code 
```js
app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

### Why it’s vulnerable
- No authentication or authorization. Any caller can request another user’s profile by manipulating `:userId`. Sensitive fields may be leaked.

### Secure fix 
```js
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'login required' });
  next();
}

function allowSelfOrRole(role) {
  return (req, res, next) => {
    const targetUserId = req.params.userId;
    if (req.user.id === targetUserId) return next();
    if (req.user.roles && req.user.roles.includes(role)) return next();
    return res.status(403).json({ error: 'forbidden' });
  };
}

app.get('/profile/:userId', requireAuth, allowSelfOrRole('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password -apiToken');
    if (!user) return res.status(404).send();
    res.json(user);
  } catch {
    res.status(500).send();
  }
});
```

### Why this fix works
- Enforces authentication and server-side authorization; excludes secrets by default.

### OWASP reference
- Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

## 2 — Broken Access Control 

### Vulnerable code 
```py
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

### Why it’s vulnerable
- Missing authentication/authorization and returns full object which may leak secrets.

### Secure fix 
```py
from flask_login import login_required, current_user
from flask import abort, jsonify

@app.route('/account/<int:user_id>')
@login_required
def get_account(user_id):
    if current_user.id != user_id and 'admin' not in current_user.roles:
        abort(403)
    user = db.query(User).filter_by(id=user_id).first_or_404()
    return jsonify({"id": user.id, "name": user.name, "email": user.email})
```

### Why this fix works
- Enforces identity and role, returns only safe fields.

### OWASP reference
- Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

---

## 3 — Cryptographic Failures 

### Vulnerable code 
```java
public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest);
}
```

### Why it’s vulnerable
- MD5 is broken and fast; no salt/work factor = trivial offline cracking.

### Secure fix 
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordUtils {
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    public static String hashPassword(String plainPassword) { return encoder.encode(plainPassword); }
    public static boolean verifyPassword(String plainPassword, String hash) { return encoder.matches(plainPassword, hash); }
}
```

### Why this fix works
- Adaptive hashing with salt and cost greatly raises cracking cost.

### OWASP reference
- Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

---

## 4 — Cryptographic Failures 

### Vulnerable code 
```py
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
```

### Why it’s vulnerable
- SHA‑1 is deprecated and fast; no salt or memory hardness.

### Secure fix 
```py
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)
```

### Why this fix works
- Salted, adaptive hashing + memory-hard w/Argon2.

### OWASP reference
- Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

---

## 5 — Injection 

### Vulnerable code 
```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

### Why it’s vulnerable
- String concatenation = SQL Injection.

### Secure fix
```java
String sql = "SELECT id, username, email FROM users WHERE username = ?";
try (PreparedStatement ps = connection.prepareStatement(sql)) {
    ps.setString(1, request.getParameter("username"));
    try (ResultSet rs = ps.executeQuery()) { /* ... */ }
}
```

### Why this fix works
- Parameterized queries keep data separate from code.

### OWASP reference
- Injection: https://owasp.org/Top10/A03_2021-Injection/

---

## 6 — Injection 

### Vulnerable code
```js
app.get('/user', (req, res) => {
    db.collection('users').findOne({ username: req.query.username }, (err, user) => {
        if (err) throw err;
        res.json(user);
    });
});
```

### Why it’s vulnerable
- Operator/object injection can subvert the query.

### Secure fix 
```js
const { query, validationResult } = require('express-validator');

app.get('/user',
  query('username').isString().trim().isLength({ min: 1, max: 100 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const username = req.query.username;
    const user = await db.collection('users').findOne({ username: { $eq: username }}, { projection: { password: 0 }});
    if (!user) return res.status(404).send();
    res.json(user);
});
```

### Why this fix works
- Ensures simple strings only; explicit equality avoids operator tricks.

### OWASP reference
- Injection: https://owasp.org/Top10/A03_2021-Injection/

---

## 7 — Insecure Design 

### Vulnerable code 
```py
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password
    db.session.commit()
    return 'Password reset'
```

### Why it’s vulnerable
- No identity verification, token, expiry, logging, or rate-limit can lead to account takeover.

### Secure design & example
- Use single-use, time-limited tokens, email the link, verify before changing password, rate-limit and log.

```py
# See runnable app: /request-reset -> /reset/<token>
# Uses itsdangerous for signed tokens, passlib for hashing, generic responses
```

### Why this fix works
- Prevents arbitrary resets and user enumeration + adds auditability.

### OWASP reference
- Insecure Design: https://owasp.org/Top10/A04_2021-Insecure_Design/

---

## 8 — Software and Data Integrity Failures

### Vulnerable code 
```html
<script src="https://cdn.example.com/lib.js"></script>
```

### Why it’s vulnerable
- If CDN is compromised, malicious JS executes in your origin.

### Secure fix (SRI + pin version)
```html
<script src="https://cdn.example.com/lib-1.2.3.min.js"
        integrity="sha384-Base64HashHere"
        crossorigin="anonymous"></script>
```
- Pin versions, self host + use SCA in CI.

### Why this fix works
- Browser verifies script content against the expected hash + prevents tampered loads.

### OWASP reference
- Vulnerable and Outdated Components / Integrity: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

---

## 9 — Server-Side Request Forgery

### Vulnerable code
```py
url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
```

### Why it’s vulnerable
- Unrestricted outbound fetch allows access to internal metadata/services.

### Secure fix
```py
import urllib.parse, socket, ipaddress, requests

ALLOWED_HOSTS = {'api.example.com', 'images.example.com'}

def is_private(host):
    ip = socket.gethostbyname(host)
    return ipaddress.ip_address(ip).is_private

def fetch_url(user_url):
    p = urllib.parse.urlparse(user_url)
    if p.scheme not in ('http','https'): raise ValueError('bad scheme')
    if p.hostname not in ALLOWED_HOSTS: raise ValueError('host not allowed')
    if is_private(p.hostname): raise ValueError('private IPs blocked')
    return requests.get(user_url, timeout=5, allow_redirects=False).text
```

### Why this fix works
- Prevents access to internal networks/resources even if user supplies a malicious URL.

### OWASP reference
- SSRF: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

---

## 10 — Identification & Authentication Failures

### Vulnerable code
```java
if (inputPassword.equals(user.getPassword())) { 
    // Login success
}
```

### Why it’s vulnerable
- Plaintext storage or naive comparison + no salted adaptive hashing + potential timing leaks + no MFA/rate limit/session hardening.

### Secure fix 
```java
BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
if (enc.matches(inputPassword, user.getPasswordHash())) {
    // success: issue session/JWT, rotate session id, set secure cookie flags
}
```

### Why this fix works
- Correct verification of salted, adaptive hashes + combined controls harden authentication.

### OWASP reference
- Identification & Authentication Failures: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

---


