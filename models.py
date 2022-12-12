from sqlalchemy import Column, String, Integer
from database import Base
from sqlalchemy.sql.expression import text
from sqlalchemy.sql.sqltypes import TIMESTAMP, LargeBinary


class Post(Base):
    __tablename__ = "credentials"

    id = Column(String, primary_key=True, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    salt = Column(LargeBinary, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
