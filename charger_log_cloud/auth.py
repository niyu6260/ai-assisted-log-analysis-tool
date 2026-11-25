from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request, status


ROLES = {"user", "expert", "admin"}


@dataclass(frozen=True)
class UserContext:
    user_id: str
    role: str


def current_user(
    request: Request,
    x_user_id: str | None = Header(default=None),
    x_user_role: str | None = Header(default=None),
) -> UserContext:
    settings = request.app.state.service.settings
    if not settings.require_auth and not x_user_id:
        return UserContext("local-developer", "admin")
    if not x_user_id or not x_user_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Trusted identity headers are required",
        )
    role = x_user_role.casefold()
    if role not in ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unknown role",
        )
    return UserContext(x_user_id[:255], role)


def require_roles(*roles: str) -> Callable[[UserContext], UserContext]:
    allowed = set(roles)

    def dependency(
        user: UserContext = Depends(current_user),
    ) -> UserContext:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return dependency
