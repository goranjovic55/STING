# STING 2.0 - Verdict Rules
"""
Score weights for verdict engine
Positive = more hostile, Negative = more clean
"""

DEFAULT_RULES = {
    # Authentication events
    "AUTH_SUCCESS": -30,
    "AUTH_FAILURE": +10,
    "AUTH_INVALID_USER": +20,

    # File operations
    "NORMAL_FILE_READ": -5,
    "FILE_READ_CANARY": +50,
    "FILE_WRITE": +15,
    "FILE_DELETE": +20,

    # Command execution
    "NORMAL_COMMAND": -2,
    "SUSPICIOUS_COMMAND": +30,
    "DANGEROUS_COMMAND": +60,

    # Network operations
    "NORMAL_NETWORK": -5,
    "WGET_EXECUTABLE": +80,
    "CURL_EXECUTABLE": +80,
    "WGET_FROM_SUSPICIOUS": +90,
    "DOWNLOAD_EXECUTE": +70,

    # Reconnaissance
    "RECON_SEQUENCE": +40,
    "PORT_SCAN": +50,
    "SERVICE_SCAN": +45,
    "NO_RECON_30S": -20,
    "CLEAN_60S": -20,

    # Resource violations
    "RESOURCE_LIMIT_HIT": +40,
    "DISK_LIMIT_EXCEEDED": +30,
    "MEMORY_LIMIT_EXCEEDED": +30,

    # Malware indicators
    "BINARY_FROM_TMP": +60,
    "EXEC_FROM_MEMORY": +70,
    "BASE64_DECODE": +25,
    "SHELL_SCRIPT_CREATE": +40,

    # Canary events
    "CANARY_HIT": +50,
    "CREDENTIAL_CANARY_HIT": +60,
    "URL_CANARY_HIT": +40,
    "DNS_CANARY_HIT": +35,
    "TOKEN_CANARY_HIT": +55,

    # Known bad indicators
    "KNOWN_BAD_IP": +100,
    "KNOWN_MALWARE_HASH": +100,
    "YARA_MATCH": +80,

    # Time-based trust (passive)
    "SESSION_5MIN_CLEAN": -10,
    "SESSION_15MIN_CLEAN": -20,
    "SESSION_30MIN_CLEAN": -30,
}

# Thresholds
SCORE_THRESHOLD_HOSTILE = 70
SCORE_THRESHOLD_TRAP = 30
SCORE_THRESHOLD_CLEAR = 0
