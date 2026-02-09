from sqlmodel import SQLModel, Field, Relationship, func, Column, DateTime
from datetime import datetime, timedelta, timezone
from typing import Optional, List

bd_time = timezone(timedelta(hours=6))

def get_utc_now():
    return datetime.now(timezone.utc)



#User Model
class UserBase(SQLModel):
    email: str = Field(unique=True, index=True)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    

class UserCreate(UserBase):
    password: str  


class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    
    # Created At: Set only once when the row is created
    created_at: datetime = Field(
        default_factory=get_utc_now,
        sa_column=Column(DateTime(timezone=True), server_default=func.now())
    )
    
    # Updated At: Changes every time the row is modified
    updated_at: datetime = Field(
        default_factory=get_utc_now,
        sa_column=Column(
            DateTime(timezone=True), 
            onupdate=func.now(), # This is the magic line
            server_default=func.now()
        )
    )
    
    notes: List['Note'] = Relationship(back_populates='owner')


class UserRead(UserBase):
    id: int

class UserUpdate(SQLModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None



class Note(SQLModel, table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    user_id : int = Field(foreign_key='user.id')
    title : str = Field(index=True)
    content : str
    is_done : bool = Field(default=False, index=True)
    owner: Optional[User] = Relationship(back_populates='notes')
    created_at: datetime = Field(
        default_factory=get_utc_now,
        sa_column=Column(DateTime(timezone=True), server_default=func.now())
    )
    updated_at: datetime = Field(
        default_factory=get_utc_now,
        sa_column=Column(
            DateTime(timezone=True), 
            onupdate=func.now(), # This is the magic line
            server_default=func.now()
        )
    )

class NoteCreate(SQLModel):
    title : str
    content : str


class NoteUpdate(SQLModel):
    title : Optional[str] = None
    content : Optional[str] = None
    is_done : Optional[bool] = None