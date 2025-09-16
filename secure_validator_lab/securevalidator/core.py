import re, html, urllib.parse, os

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.fullmatch(pattern, email) is not None

def validate_url(url: str) -> bool:
    """Validate URL and prevent basic SSRF vectors."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
    except Exception:
        return False

def validate_filename(filename: str) -> bool:
    """Prevent path traversal attacks."""
    if ".." in filename or filename.startswith("/") or "\\" in filename:
        return False
    return True

def sanitize_sql_input(input_str: str) -> str:
    """Sanitize SQL input to prevent SQL injection."""
    pattern = r"\b(SELECT|INSERT|DELETE|UPDATE|DROP|JOIN|WHERE)\b"
    sanitized = re.sub(pattern, "", input_str, flags=re.IGNORECASE)
    return sanitized.strip()

def sanitize_html_input(html_str: str) -> str:
    """Escape HTML input to prevent XSS."""
    return html.escape(html_str)
