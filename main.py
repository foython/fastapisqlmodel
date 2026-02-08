from fastapi import FastAPI, HTTPException, status, Depends
from database_settings import engine
from sqlmodel import SQLModel, Session, select
from models import Note, NoteCreate, NoteUpdate
from typing import List, Optional
from pwdlib import PasswordHash

app = FastAPI()



password_hash = PasswordHash.recommended()

def hash_pass(password: str):
    return password_hash.hash(password)

def verify_pass(plain_pass, hashed_pass):
    return password_hash.verify(plain_pass, hashed_pass)




from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")




@app.on_event("startup")
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

@app.get('/notes', response_model=List[Note])
def get_notes(is_done : Optional[bool]=None, session: Session = Depends(get_session)):
    statement = select(Note)
    if is_done is not None:
        note = statement.where(Note.is_done == is_done)
        note = note.order_by(Note.created_at.desc())
        return session.exec(note).all()
    return session.exec(statement).all()


@app.get('/notes/{id}', response_model=Note)
def get_notes(id:int, session: Session = Depends(get_session)):
    note = session.get(Note, id)
    if not note:
        raise HTTPException(status_code=400, detail='Note not found')
    return note


@app.post('/notes', response_model=Note)
def add_note(payload:NoteCreate, session: Session = Depends(get_session)):
    note = Note.model_validate(payload)
    session.add(note)
    session.commit()
    session.refresh(note)
    return note

from models import UserRead, UserCreate, User, UserUpdate



@app.post("/register", response_model=UserRead) 
def register(user_in: UserCreate, session: Session = Depends(get_session)):

    db_user = User(
        email=user_in.email,
        first_name=user_in.first_name,
        last_name=user_in.last_name,
        hashed_password=hash_pass(user_in.password) # Hash it!
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user # hashed_password is removed automatically by response_model



from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordRequestForm



SECRET_KEY = "4a21425618f42706f496382784ace5e4e9db7988ac464b20bb43d873afda5b81" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    # Ensure expiration is in UTC
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    # 1. Look up user (form_data.username is the email from Swagger)
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    
    # 2. Verify password
    if not user or not verify_pass(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    # 3. Create and return the token
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}



def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    # Find the user in the database
    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise credentials_exception
    return user


@app.get("/users/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user



@app.patch("/users/me", response_model=UserRead)
def update_my_data(
    update_data: UserUpdate, 
    current_user: User = Depends(get_current_user), # The 'Lock' is here
    session: Session = Depends(get_session)
):
    # Update only the fields provided
    user_data = update_data.model_dump(exclude_unset=True)
    for key, value in user_data.items():
        setattr(current_user, key, value)
        
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user