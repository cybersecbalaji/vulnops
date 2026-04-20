# Import all models so Alembic's autogenerate can detect them
from app.models.organization import Organization, OrgSettings
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.vulnerability import Vulnerability
from app.models.audit_log import AuditLog
from app.models.asset import Asset

__all__ = ["Organization", "OrgSettings", "User", "RefreshToken", "Vulnerability", "AuditLog", "Asset"]
