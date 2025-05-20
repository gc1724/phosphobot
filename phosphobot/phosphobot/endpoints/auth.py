# phosphobot/endpoints/auth.py

import time

from fastapi import APIRouter, HTTPException
from loguru import logger

from phosphobot.models import (
    AuthResponse,
    LoginCredentialsRequest,
    SessionReponse,
    Session,
    StatusResponse,
)
from phosphobot.posthog import add_email_to_posthog
from phosphobot.sentry import add_email_to_sentry

from phosphobot.auth_fake import (
    signup as fake_signup,
    signin as fake_signin,
    save_session_local,
    delete_session_local,
    get_session_local,
)

router = APIRouter(tags=["auth"])


@router.post("/auth/signup", response_model=SessionReponse)
async def signup(
    credentials: LoginCredentialsRequest,
) -> SessionReponse:
    """
    Sign up a new user (in-memory fake).
    """
    try:
        session: Session = await fake_signup(credentials.email, credentials.password)
        save_session_local(session)
        add_email_to_posthog(session.user_email)
        add_email_to_sentry(session.user_email)
        return SessionReponse(message="Signup successful", session=session)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/auth/signin", response_model=SessionReponse)
async def signin(
    credentials: LoginCredentialsRequest,
) -> SessionReponse:
    """
    Sign in an existing user (in-memory fake).
    """
    try:
        session: Session = await fake_signin(credentials.email, credentials.password)
        save_session_local(session)
        add_email_to_posthog(session.user_email)
        add_email_to_sentry(session.user_email)
        return SessionReponse(message="Signin successful", session=session)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/auth/logout", response_model=StatusResponse)
async def logout() -> StatusResponse:
    """
    Log out the current user by clearing the in-memory session.
    """
    delete_session_local()
    return StatusResponse(message="Logout successful")


@router.get("/auth/check_auth", response_model=AuthResponse)
async def is_authenticated() -> AuthResponse:
    """
    Check whether a user is currently authenticated.
    """
    session = get_session_local()
    if session:
        return AuthResponse(authenticated=True, session=session)
    return AuthResponse(authenticated=False)
