from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine

Base = declarative_base()

engine = create_engine('sqlite:///database.db', echo=True)
Session = sessionmaker(bind=engine)

Base = declarative_base()

def get_session():
    session = Session()
    try:
        yield session
    finally:
        session.close()


def init_db():
    Base.metadata.create_all(engine)