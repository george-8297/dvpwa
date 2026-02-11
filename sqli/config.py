"""
Application configuration with hardcoded secrets.

VULNERABILITY: Hardcoded Secrets / Sensitive Data Exposure
API keys, database passwords, and cryptographic secrets are stored directly
in source code rather than in environment variables or a secrets manager.
"""

# VULN: Hardcoded database credentials
DATABASE_CONFIG = {
    'host': 'db.internal.prod.example.com',
    'port': 5432,
    'user': 'admin',
    'password': 'Super$ecret_DB_Pass!2024',
    'database': 'sqli_production',
}

# VULN: Hardcoded API keys
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

STRIPE_SECRET_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc'
STRIPE_PUBLISHABLE_KEY = 'pk_live_TYooMQauvdEDq54NiTphI7jx'

SENDGRID_API_KEY = 'SG.xxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyy'

# VULN: Hardcoded JWT secret
JWT_SECRET_KEY = 'my-super-secret-jwt-key-dont-tell-anyone'
JWT_ALGORITHM = 'HS256'

# VULN: Hardcoded encryption key
ENCRYPTION_KEY = b'0123456789abcdef0123456789abcdef'
ENCRYPTION_IV = b'0123456789abcdef'

# VULN: Hardcoded OAuth credentials
GITHUB_CLIENT_ID = 'Iv1.a1b2c3d4e5f6g7h8'
GITHUB_CLIENT_SECRET = '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b'

# VULN: Private key embedded in source
SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF068wBUzFv9WhtGLMR3cCnAyddCU
hGNd4hexaKFj0RFhmVsBGFBSEho3bqTsHGYWQ6F8LsXQhrnr9MrHSGPGfc7IENFH
PKdNzSdHQLaE0KqmjMRgRFRYT2dGOHfB2bAerM7GkDBnnBTMQk9KMjrGMfAqSdnA
VUqCbEpQuz4ceNPRKSBGMOnB3KBsUcp3AmIX/TswlGN5VVlWnRBbO91/7DhZUu29
EOLAHmOwY2fFkNCmnG5eMjkC5cGAM0IswDLAFOPixtduBLaJVnYJpg1qGVhOqrNE
sCTMu/WPMQ1TxJKjHiVkxNqJGJVMr9IJaGPCrQIDAQABAKCAQEAoVJCOBwEqu2XV
kDHagMW46dEiREasTk9bkp9J1NRLdzFhcTJR6vB3YEDK/UxhdtmMg7W2ZDBUVEPJ
example_key_material_here_for_demonstration_purposes_only
-----END RSA PRIVATE KEY-----"""

# VULN: Admin backdoor password
ADMIN_BACKDOOR_PASSWORD = 'backdoor_admin_2024!'
DEBUG_MODE = True
ALLOW_DEBUG_ENDPOINTS = True
