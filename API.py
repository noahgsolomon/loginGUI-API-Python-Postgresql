import hashlib
import os
from fastapi import FastAPI, Query, Request
from datetime import time
from pydantic import BaseModel
import psycopg2 as psycopg2
from psycopg2.extras import RealDictCursor
from starlette import status
import models
from database import engine

while True:
    try:
        conn = psycopg2.connect(host='localhost',
                                database='user', user='postgres', password='password', cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        print("database connection was successful")
        break
    except Exception as error:
        print("Connecting to database failed")
        time.sleep(2)

models.Base.metadata.create_all(bind=engine)

app = FastAPI()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    message: str


class CreateAccountRequest(BaseModel):
    username: str
    password: str


class CreateAccountResponse(BaseModel):
    message: str


@app.post("/login", status_code=status.HTTP_200_OK, response_model=LoginResponse)
def login(login: LoginRequest):
    username = login.username
    password = login.password
    cursor.execute("""SELECT salt, password FROM credentials WHERE username = '{}'""".format(username))
    details = cursor.fetchone()
    if details:
        # grabs stored random salt associates with username in database
        stored_salt = details['salt']
        # grabs stored string password in database that was attained from hashed_password
        stored_pass = details['password']
        # adding password sequence of bytes in utf-8 format to the salt bytes
        salted_password = password.encode('utf-8') + stored_salt
        # same thing as create_account. We did the same sequences with the same salt, so we should get the same password
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        print(hashed_password)
        if stored_pass == str(hashed_password):
            return {"message": f"welcome in, {username}"}
        else:
            return {"message": "Invalid Credentials"}


@app.post("/create", status_code=status.HTTP_201_CREATED, response_model=CreateAccountResponse)
def create(create: CreateAccountRequest):
    username = create.username
    password = create.password

    salt = os.urandom(16)
    # adding password sequence of bytes in utf-8 format to the salt bytes
    salted_password = password.encode('utf-8') + salt
    # calculates the SHA-256 hash of the salted_password bytes and returns it as a bytes object. Finally,
    # the hexdigest() method is called on the returned bytes object, which converts the hash to a string of hexadecimal digits
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    cursor.execute("""SELECT * FROM credentials WHERE username = '{}'""".format(username))
    post = cursor.fetchone()
    if not post:
        cursor.execute("""INSERT INTO credentials (username, password, salt) VALUES (%s, %s, %s)""",
                       (username, hashed_password, salt))
        conn.commit()
        return {"message": "successfully created account!"}
    else:
        return {"message": "username is already in use!"}