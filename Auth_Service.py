

##########################################################################################################

import os
import secrets
import datetime
import jwt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import jwt as pyjwt
from dotenv import load_dotenv

#########################################################################################################
load_dotenv()

app = FastAPI()

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv('SECRET_AUTH_KEY')
logger.info(f"Generated SECRET_KEY: {SECRET_KEY}")

# Mock database : We can add other users to this.
users_db = {
    "Dev": generate_password_hash("Dev@1234"),
    "Mahsa":generate_password_hash("Mahsa@1234"),
    "Stacy":generate_password_hash("Stacy@1234"),
    "Test": generate_password_hash("Test@1234")
}
logger.info(f"Mock database: {users_db}")

class LoginCredentials(BaseModel):
    username: str
    password: str

security = HTTPBearer()


def create_token(username: str) -> str:
    try:
        
        payload = {
            'sub': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1) 
        }
        # Encode
        token = pyjwt.encode(payload, SECRET_KEY, algorithm='HS256')
        logger.info(f"Generated token for {username}")
        return token
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Unable to generate authentication token"
        )

def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        # Decode 
        token = credentials.credentials
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        logger.info(f"Token validated for {decoded_token['sub']}")
        return decoded_token['sub']
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired.")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")



@app.post("/login")
async def login(credentials: LoginCredentials):
    username = credentials.username
    password = credentials.password
    logger.info(f"Attempting login for username: {username}")

    try:
        # Validate
        if username in users_db:
            if check_password_hash(users_db[username], password):
                print("check")
                try:
                    token = create_token(username)
                    logger.info(f"Token generated successfully for {username}")
                    return {"access_token": token, "token_type": "bearer"}
                except Exception as e:
                    logger.error(f"Error during token creation: {e}")
                    raise HTTPException(status_code=500, detail="Token generation failed")
            else:
                logger.warning(f"Password mismatch for {username}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
        else:
            logger.warning(f"Username {username} not found in database")
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        logger.error(f"Internal Server Error during login: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/protected")
async def protected_route(username: str = Depends(validate_token)):
    return {"message": f"Hello {username}, you are authorized!",
             "status": "Authorized"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
