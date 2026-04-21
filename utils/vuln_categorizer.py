def categorize_vulnerability(issue, description):
    text = (issue + " " + description).lower()

    # SSL Vulnerabilities
    if "heartbleed" in text:
        return "heartbleed"
    elif "poodle" in text:
        return "poodle"
    elif "crime" in text:
        return "crime"
    elif "breach" in text:
        return "breach"
    elif "logjam" in text:
        return "logjam"
    elif "robot" in text:
        return "robot"

    # Config Issues
    elif "weak" in text:
        return "weak_cipher"
    elif "deprecated" in text:
        return "deprecated_protocol"
    elif "tls 1.0" in text or "tls1.0" in text:
        return "tls1.0"
    elif "tls 1.1" in text:
        return "tls1.1"
    elif "forward secrecy" in text:
        return "no_forward_secrecy"

    # Certificate Issues
    elif "expired" in text:
        return "expired_cert"
    elif "mismatch" in text:
        return "hostname_mismatch"
    elif "ocsp" in text:
        return "no_ocsp"

    return "other"