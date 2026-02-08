from sqlmodel import SQLModel, create_engine, Session

url = 'postgresql://admin:123456@localhost:5432/fastapi'
engine = create_engine(url, echo=True)

