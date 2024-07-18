from database import Base
from sqlalchemy import Column, Integer, String
from pydantic import BaseModel


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True)
    username = Column(String, unique=True)
    password = Column(String)

class UserSchema(BaseModel):
    name: str
    email: str
    username: str
    password: str


class TokenSchema(BaseModel):
    access_token: str
    token_type: str