"""Security helpers for password hashing and verification."""
import base64
import hashlib
import hmac
import secrets

try:
    import bcrypt
except ImportError:  # pragma: no cover - bcrypt optional
    bcrypt = None

DEFAULT_METHOD = 'pbkdf2:sha256'
DEFAULT_ITERATIONS = 260000


def generate_password_hash(password, method=DEFAULT_METHOD, salt_length=16):
    """Generate a password hash compatible with Werkzeug's pbkdf2 format."""
    if not method.startswith('pbkdf2:'):
        raise ValueError("Unsupported hashing method for this custom function")

    iterations = DEFAULT_ITERATIONS
    hash_name = 'sha256'
    method_parts = method.split(':')
    if len(method_parts) >= 2:
        hash_name = method_parts[1]
        if len(method_parts) >= 3:
            try:
                iterations = int(method_parts[2])
            except ValueError:
                pass

    salt = secrets.token_hex(salt_length)
    pwdhash = hashlib.pbkdf2_hmac(
        hash_name,
        password.encode('utf-8'),
        bytes.fromhex(salt),
        iterations
    )
    pwdhash_b64 = base64.b64encode(pwdhash).decode('ascii')
    return f'pbkdf2:{hash_name}:{iterations}${salt}${pwdhash_b64}'


def check_password_hash(pwhash, password):
    """Verify password against stored hash supporting bcrypt and pbkdf2."""
    try:
        if pwhash.startswith(('$2b$', '$2a$', '$2y$')):
            if bcrypt is None:
                print("bcrypt not available, cannot verify bcrypt hash")
                return False
            return bcrypt.checkpw(password.encode('utf-8'), pwhash.encode('utf-8'))

        if pwhash.startswith('pbkdf2:'):
            parts = pwhash.split('$', 2)
            if len(parts) != 3:
                return False
            method, salt, hashval = parts
            method_parts = method.split(':')
            if len(method_parts) < 2:
                return False
            hash_name = method_parts[1]
            iterations = DEFAULT_ITERATIONS
            if len(method_parts) >= 3:
                try:
                    iterations = int(method_parts[2])
                except ValueError:
                    pass

            pwdhash_check = hashlib.pbkdf2_hmac(
                hash_name,
                password.encode('utf-8'),
                bytes.fromhex(salt),
                iterations
            )
            pwdhash_check_b64 = base64.b64encode(pwdhash_check).decode('ascii')
            return hmac.compare_digest(pwdhash_check_b64, hashval)

        # Fallback to Werkzeug implementation if available
        from werkzeug.security import check_password_hash as werkzeug_check
        return werkzeug_check(pwhash, password)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"Password verification error: {str(exc)}")
        return False
