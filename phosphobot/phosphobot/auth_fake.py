from typing import Dict
from passlib.context import CryptContext
from phosphobot.models import Session

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

_USERS: Dict[str, str] = {}

async def signup(email: str, password: str) -> Session:
    if email in _USERS:
        raise ValueError("User already exists")
    hashed = pwd_ctx.hash(password)
    _USERS[email] = hashed
    return Session(
        user_id=str(hash(email) % 10_000),
        user_email=email,
        email_confirmed=True,
        access_token="fake-access-token",
        refresh_token="fake-refresh-token",
        expires_at=2**31 - 1,
    )

async def signin(email: str, password: str) -> Session:
    hashed = _USERS.get(email)
    if not hashed or not pwd_ctx.verify(password, hashed):
        raise ValueError("Invalid credentials")
    return Session(
        user_id=str(hash(email) % 10_000),
        user_email=email,
        email_confirmed=True,
        access_token="fake-access-token",
        refresh_token="fake-refresh-token",
        expires_at=2**31 - 1,
    )


from phosphobot.models import Session

_CURRENT_SESSION: Session | None = None

def save_session_local(session: Session):
    global _CURRENT_SESSION
    _CURRENT_SESSION = session

def delete_session_local():
    global _CURRENT_SESSION
    _CURRENT_SESSION = None

def get_session_local() -> Session | None:
    return _CURRENT_SESSION