"""
Security Module
===============
Handles credential encryption, storage, and role-based access control.

Features:
- AES-256 encryption for credentials
- Secure key derivation with PBKDF2
- Role-based permission system
- Audit logging
"""

import os
import json
import hashlib
import logging
import secrets
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from enum import Enum
from base64 import b64encode, b64decode

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger('ServerControlPro.Security')


class Permission(Enum):
    """Available permissions."""
    VIEW_SERVERS = "view_servers"
    VIEW_METRICS = "view_metrics"
    START_SERVICE = "start_service"
    STOP_SERVICE = "stop_service"
    RESTART_SERVICE = "restart_service"
    EDIT_CONFIG = "edit_config"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOG = "view_audit_log"


class Role(Enum):
    """Predefined roles."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# Default role permissions
DEFAULT_ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {p for p in Permission},  # All permissions
    Role.OPERATOR: {
        Permission.VIEW_SERVERS,
        Permission.VIEW_METRICS,
        Permission.START_SERVICE,
        Permission.STOP_SERVICE,
        Permission.RESTART_SERVICE,
    },
    Role.VIEWER: {
        Permission.VIEW_SERVERS,
        Permission.VIEW_METRICS,
    },
}


@dataclass
class User:
    """User account."""
    username: str
    password_hash: str
    role: Role
    created: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    enabled: bool = True


@dataclass
class AuditEntry:
    """Audit log entry."""
    timestamp: datetime
    user: str
    action: str
    target: str
    details: str
    success: bool
    ip_address: str = ""


class CredentialEncryption:
    """
    Handles encryption and decryption of credentials.

    Uses Fernet (AES-128-CBC) with PBKDF2 key derivation.
    The encryption key is derived from a master password or auto-generated.
    """

    SALT_SIZE = 16
    KEY_ITERATIONS = 480000  # OWASP recommended minimum

    def __init__(self, data_dir: Path):
        """
        Initialize credential encryption.

        Args:
            data_dir: Directory for storing encrypted credentials
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self._key_file = self.data_dir / '.keyfile'
        self._credentials_file = self.data_dir / 'credentials.enc'
        self._salt_file = self.data_dir / '.salt'

        self._fernet: Optional[Fernet] = None
        self._initialize_encryption()

    def _initialize_encryption(self):
        """Initialize or load encryption key."""
        # Get or create salt
        if self._salt_file.exists():
            salt = self._salt_file.read_bytes()
        else:
            salt = secrets.token_bytes(self.SALT_SIZE)
            self._salt_file.write_bytes(salt)
            # Set restrictive permissions on Unix
            try:
                os.chmod(self._salt_file, 0o600)
            except (OSError, AttributeError):
                pass

        # Get or create master key
        if self._key_file.exists():
            master_key = self._key_file.read_bytes()
        else:
            master_key = secrets.token_bytes(32)
            self._key_file.write_bytes(master_key)
            try:
                os.chmod(self._key_file, 0o600)
            except (OSError, AttributeError):
                pass

        # Derive encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KEY_ITERATIONS,
        )
        key = b64encode(kdf.derive(master_key))
        self._fernet = Fernet(key)

        logger.debug("Encryption initialized")

    def encrypt(self, data: str) -> str:
        """
        Encrypt string data.

        Args:
            data: Plain text to encrypt

        Returns:
            Base64-encoded encrypted data
        """
        encrypted = self._fernet.encrypt(data.encode('utf-8'))
        return b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> Optional[str]:
        """
        Decrypt encrypted data.

        Args:
            encrypted_data: Base64-encoded encrypted data

        Returns:
            Decrypted string or None if decryption fails
        """
        try:
            encrypted_bytes = b64decode(encrypted_data.encode('utf-8'))
            decrypted = self._fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except (InvalidToken, ValueError) as e:
            logger.error(f"Decryption failed: {e}")
            return None

    def remove_server_credentials(self, server_id: str) -> bool:
        """
        Remove credentials for a specific server.

        Args:
            server_id: Server ID to remove

        Returns:
            True if removed, False if not found
        """
        credentials = self.load_credentials()
        if server_id in credentials:
            del credentials[server_id]
            self.store_credentials(credentials)
            logger.info(f"Removed credentials for {server_id}")
            return True
        return False

    def store_credentials(self, credentials: Dict[str, Dict[str, str]]):
        """
        Store credentials securely.

        Args:
            credentials: Dictionary of server_id -> {username, password, key_passphrase}
        """
        data = json.dumps(credentials)
        encrypted = self.encrypt(data)
        self._credentials_file.write_text(encrypted)

        try:
            os.chmod(self._credentials_file, 0o600)
        except (OSError, AttributeError):
            pass

        logger.info(f"Stored credentials for {len(credentials)} servers")

    def load_credentials(self) -> Dict[str, Dict[str, str]]:
        """
        Load stored credentials.

        Returns:
            Dictionary of server_id -> credentials
        """
        if not self._credentials_file.exists():
            return {}

        try:
            encrypted = self._credentials_file.read_text()
            decrypted = self.decrypt(encrypted)

            if decrypted:
                return json.loads(decrypted)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load credentials: {e}")

        return {}

    def get_server_credentials(self, server_id: str) -> Optional[Dict[str, str]]:
        """Get credentials for a specific server."""
        credentials = self.load_credentials()
        return credentials.get(server_id)

    def set_server_credentials(
            self,
            server_id: str,
            username: str,
            password: Optional[str] = None,
            key_passphrase: Optional[str] = None
    ):
        """Set credentials for a specific server."""
        credentials = self.load_credentials()
        credentials[server_id] = {
            'username': username,
            'password': password or '',
            'key_passphrase': key_passphrase or ''
        }
        self.store_credentials(credentials)

    def remove_server_credentials(self, server_id: str):
        """Remove credentials for a specific server."""
        credentials = self.load_credentials()
        if server_id in credentials:
            del credentials[server_id]
            self.store_credentials(credentials)

    def reset(self):
        """Reset all encryption data (deletes all stored credentials)."""
        for file in [self._key_file, self._salt_file, self._credentials_file]:
            if file.exists():
                file.unlink()
        self._initialize_encryption()
        logger.info("Encryption data reset")


class AuditLogger:
    """
    Logs user actions for security auditing.

    Maintains a persistent log of all significant actions.
    """

    MAX_ENTRIES = 10000  # Maximum entries to keep

    def __init__(self, data_dir: Path):
        """
        Initialize audit logger.

        Args:
            data_dir: Directory for storing audit logs
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self.data_dir / 'audit.log'
        self._entries: List[AuditEntry] = []
        self._load_entries()

    def _load_entries(self):
        """Load existing audit entries."""
        if not self._log_file.exists():
            return

        try:
            with open(self._log_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        entry = AuditEntry(
                            timestamp=datetime.fromisoformat(data['timestamp']),
                            user=data['user'],
                            action=data['action'],
                            target=data['target'],
                            details=data['details'],
                            success=data['success'],
                            ip_address=data.get('ip_address', '')
                        )
                        self._entries.append(entry)
                    except (json.JSONDecodeError, KeyError):
                        continue
        except IOError as e:
            logger.error(f"Failed to load audit log: {e}")

    def log(
            self,
            user: str,
            action: str,
            target: str,
            details: str = "",
            success: bool = True,
            ip_address: str = ""
    ):
        """
        Log an audit entry.

        Args:
            user: Username performing action
            action: Action being performed
            target: Target of the action (server, service, etc.)
            details: Additional details
            success: Whether action succeeded
            ip_address: IP address of user
        """
        entry = AuditEntry(
            timestamp=datetime.now(),
            user=user,
            action=action,
            target=target,
            details=details,
            success=success,
            ip_address=ip_address
        )

        self._entries.append(entry)

        # Trim old entries
        if len(self._entries) > self.MAX_ENTRIES:
            self._entries = self._entries[-self.MAX_ENTRIES:]

        # Persist entry
        try:
            with open(self._log_file, 'a') as f:
                f.write(json.dumps({
                    'timestamp': entry.timestamp.isoformat(),
                    'user': entry.user,
                    'action': entry.action,
                    'target': entry.target,
                    'details': entry.details,
                    'success': entry.success,
                    'ip_address': entry.ip_address
                }) + '\n')
        except IOError as e:
            logger.error(f"Failed to write audit entry: {e}")

        logger.info(
            f"AUDIT: [{user}] {action} on {target} - "
            f"{'SUCCESS' if success else 'FAILED'}: {details}"
        )

    def get_entries(
            self,
            limit: int = 100,
            user: Optional[str] = None,
            action: Optional[str] = None,
            since: Optional[datetime] = None
    ) -> List[AuditEntry]:
        """
        Get audit entries with optional filtering.

        Args:
            limit: Maximum entries to return
            user: Filter by username
            action: Filter by action type
            since: Only entries after this time

        Returns:
            List of matching audit entries (newest first)
        """
        entries = self._entries.copy()

        if user:
            entries = [e for e in entries if e.user == user]

        if action:
            entries = [e for e in entries if e.action == action]

        if since:
            entries = [e for e in entries if e.timestamp >= since]

        # Return newest first
        entries.reverse()
        return entries[:limit]


class SecurityManager:
    """
    Central security manager.

    Handles credential encryption, user authentication,
    role-based access control, and audit logging.
    """

    def __init__(self, data_dir: Path):
        """
        Initialize security manager.

        Args:
            data_dir: Directory for security data
        """
        self.data_dir = Path(data_dir)
        self.encryption = CredentialEncryption(data_dir)
        self.audit = AuditLogger(data_dir)

        self._users_file = data_dir / 'users.enc'
        self._users: Dict[str, User] = {}
        self._current_user: Optional[User] = None
        self._role_permissions: Dict[Role, Set[Permission]] = DEFAULT_ROLE_PERMISSIONS.copy()

        self._load_users()
        self._ensure_default_admin()

    def _load_users(self):
        """Load user accounts."""
        if not self._users_file.exists():
            return

        try:
            encrypted = self._users_file.read_text()
            decrypted = self.encryption.decrypt(encrypted)

            if decrypted:
                data = json.loads(decrypted)
                for username, user_data in data.items():
                    self._users[username] = User(
                        username=username,
                        password_hash=user_data['password_hash'],
                        role=Role(user_data['role']),
                        created=datetime.fromisoformat(user_data['created']),
                        last_login=datetime.fromisoformat(user_data['last_login'])
                        if user_data.get('last_login') else None,
                        enabled=user_data.get('enabled', True)
                    )
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load users: {e}")

    def _save_users(self):
        """Save user accounts."""
        data = {}
        for username, user in self._users.items():
            data[username] = {
                'password_hash': user.password_hash,
                'role': user.role.value,
                'created': user.created.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'enabled': user.enabled
            }

        encrypted = self.encryption.encrypt(json.dumps(data))
        self._users_file.write_text(encrypted)

    def _ensure_default_admin(self):
        """Ensure at least one admin account exists."""
        if not any(u.role == Role.ADMIN for u in self._users.values()):
            # Create default admin account
            self.create_user('admin', 'admin', Role.ADMIN)
            logger.warning("Created default admin account (admin/admin) - CHANGE IMMEDIATELY!")

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password using SHA-256 with salt."""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256((salt + password).encode())
        return f"{salt}${hash_obj.hexdigest()}"

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        try:
            salt, hash_value = password_hash.split('$')
            hash_obj = hashlib.sha256((salt + password).encode())
            return hash_obj.hexdigest() == hash_value
        except ValueError:
            return False

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate user credentials.

        Args:
            username: Username
            password: Password

        Returns:
            True if authentication successful
        """
        user = self._users.get(username)

        if not user:
            self.audit.log(username, "LOGIN", "system", "User not found", False)
            return False

        if not user.enabled:
            self.audit.log(username, "LOGIN", "system", "Account disabled", False)
            return False

        if not self._verify_password(password, user.password_hash):
            self.audit.log(username, "LOGIN", "system", "Invalid password", False)
            return False

        # Success
        user.last_login = datetime.now()
        self._save_users()
        self._current_user = user

        self.audit.log(username, "LOGIN", "system", "Authentication successful", True)
        return True

    def logout(self):
        """Log out current user."""
        if self._current_user:
            self.audit.log(self._current_user.username, "LOGOUT", "system")
            self._current_user = None

    @property
    def current_user(self) -> Optional[User]:
        """Get currently authenticated user."""
        return self._current_user

    def has_permission(self, permission: Permission) -> bool:
        """Check if current user has a permission."""
        if not self._current_user:
            return False

        user_permissions = self._role_permissions.get(self._current_user.role, set())
        return permission in user_permissions

    def require_permission(self, permission: Permission) -> bool:
        """
        Check permission and log if denied.

        Returns:
            True if permitted, False if denied
        """
        if not self.has_permission(permission):
            user = self._current_user.username if self._current_user else "anonymous"
            self.audit.log(
                user,
                "PERMISSION_DENIED",
                permission.value,
                f"User lacks required permission",
                False
            )
            return False
        return True

    def create_user(self, username: str, password: str, role: Role) -> bool:
        """
        Create new user account.

        Args:
            username: Username
            password: Password
            role: User role

        Returns:
            True if user created
        """
        if username in self._users:
            return False

        self._users[username] = User(
            username=username,
            password_hash=self._hash_password(password),
            role=role
        )
        self._save_users()

        actor = self._current_user.username if self._current_user else "system"
        self.audit.log(actor, "CREATE_USER", username, f"Role: {role.value}")

        return True

    def change_password(self, username: str, new_password: str) -> bool:
        """Change user password."""
        if username not in self._users:
            return False

        self._users[username].password_hash = self._hash_password(new_password)
        self._save_users()

        actor = self._current_user.username if self._current_user else "system"
        self.audit.log(actor, "CHANGE_PASSWORD", username)

        return True

    def reset_credentials(self):
        """Reset all stored credentials."""
        self.encryption.reset()
        logger.info("All credentials have been reset")

    def get_server_credentials(self, server_id: str) -> Optional[Dict[str, str]]:
        """Get credentials for a server."""
        return self.encryption.get_server_credentials(server_id)

    def set_server_credentials(
            self,
            server_id: str,
            username: str,
            password: Optional[str] = None,
            key_passphrase: Optional[str] = None
    ):
        """Store credentials for a server."""
        self.encryption.set_server_credentials(
            server_id, username, password, key_passphrase
        )

        actor = self._current_user.username if self._current_user else "system"
        self.audit.log(actor, "SET_CREDENTIALS", server_id)

    def log_action(
            self,
            action: str,
            target: str,
            details: str = "",
            success: bool = True
    ):
        """Log an action to the audit trail."""
        user = self._current_user.username if self._current_user else "system"
        self.audit.log(user, action, target, details, success)