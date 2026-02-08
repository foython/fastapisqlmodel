from sqlmodel import SQLModel, Field
from datetime import datetime, timedelta, timezone
from typing import Optional

bd_time = timezone(timedelta(hours=6))

def get_bd_time():
    return datetime.now(bd_time)

class Note(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    title : str = Field(index=True)
    content : str
    is_done : bool = Field(default=False, index=True)
    created_at : datetime = Field(default_factory=get_bd_time)

class NoteCreate(SQLModel):
    title : str
    content : str


class NoteUpdate(SQLModel):
    title : Optional[str] = None
    content : Optional[str] = None
    is_done : Optional[str] = None

#User Model
class UserBase(SQLModel):
    email: str = Field(unique=True, index=True)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    created_at: datetime = Field(default_factory=get_bd_time)

class UserCreate(UserBase):
    password: str  


class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str

class UserRead(UserBase):
    id: int

class UserUpdate(SQLModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None