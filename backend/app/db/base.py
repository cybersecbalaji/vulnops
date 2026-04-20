"""
SQLAlchemy declarative base and ORM base class.

All models inherit from Base. The OrgScopedMixin is applied to every model
that stores org data — it enforces the requirement that every query includes
an org_id filter (enforced at the service layer via OrgScopedRepository).
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
