from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional

from authx import AuthX, AuthXConfig, RequestToken, TokenPayload
from authx.exceptions import AuthXException

app = FastAPI()

config = AuthXConfig(
    JWT_ALGORITHM="HS256",
    JWT_SECRET_KEY="SECRET_KEY",
    JWT_TOKEN_LOCATION=["headers", "cookies"],
    JWT_COOKIE_CSRF_PROTECT=False,
)
auth = AuthX(config=config)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="http://localhost:8081/api/v1/users/auth/login/"
)


class User(BaseModel):
    username: str
    password: str


# Dummy database pengguna
fake_users_db = {
    "user@example.com": {
        "username": "user@example.com",
        "password": "password",
        "id": "user_id_123",
    }
}


@app.post("/login")
async def login(user: User, response: Response):
    # Verifikasi pengguna
    user_data = fake_users_db.get(user.username)
    if not user_data or user_data["password"] != user.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Buat token akses dan refresh
    access_token = auth.create_access_token(uid=user_data["id"], fresh=True)
    refresh_token = auth.create_refresh_token(uid=user_data["id"])

    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/refresh")
async def refresh_token(request: Request, response: Response):
    try:
        # Mendapatkan token refresh dari cookies
        refresh_token = await auth.get_refresh_token_from_request(request)
        payload = auth.verify_token(refresh_token)

        # Buat token akses baru
        access_token = auth.create_access_token(uid=payload.sub, fresh=False)

        # Set token akses baru dalam cookies
        auth.set_access_cookies(access_token, response)

        return {"access_token": access_token}
    except AuthXException as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/protected")
async def protected_endpoint(
    token: TokenPayload = Depends(auth.token_required("access")),
):
    # Endpoint yang dilindungi dengan token akses
    return {"message": "You are accessing a protected endpoint!", "user_id": token.sub}


# Menjalankan aplikasi FastAPI
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
