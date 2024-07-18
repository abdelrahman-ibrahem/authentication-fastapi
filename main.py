from fastapi import FastAPI, Depends
from database import Base, engine
import models
from auth import router, get_current_user
from database import get_session
from sqlalchemy.orm import Session
from typing import Annotated


app = FastAPI()
app.include_router(router)
models.Base.metadata.create_all(engine)

db_dependency = Annotated[Session, Depends(get_session)]
user_dependency = Annotated[dict, Depends(get_current_user)]



@app.get('/get-profile/')
async def get_profile(user: user_dependency, db: db_dependency):
    print(user)
    user_db = db.query(models.User).filter(models.User.username == user['username']).first()
    return {'username': user_db.username, 'email': user_db.email, 'name': user_db.name}