
# security_deps.py (Option A: cookie fallback)
from typing import Optional, List, Dict
from fastapi import HTTPException, status, Request
import os
import httpx
from jose import jwt

# Simple principal container
class Principal:
    def __init__(self, sub: str, scopes: List[str], raw: Dict):
        self.sub = sub
        self.scopes = scopes
        self.raw = raw

# Environment for Okta validation
OKTA_ISSUER = (os.getenv("OKTA_ISSUER") or "").strip()
OKTA_METADATA_URL = (os.getenv("OKTA_METADATA_URL") or "").strip()
OKTA_AUDIENCE = (os.getenv("OKTA_AUDIENCE") or "api://default").strip()

BUSINESS_PREFIXES = ("orders:", "customers:", "invoices:", "agreements:", "users:")

async def _fetch_json(url: str) -> Dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()

def _bearer_from_header_or_cookie(authorization: Optional[str], request: Request) -> str:
    # Prefer Authorization header
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    # Fallback to secure HTTP-only cookies set by /callback
    token = request.cookies.get("api_access_token") or request.cookies.get("okta_access_token")
    if token:
        return token
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

async def require_auth(authorization: Optional[str], base_url: str, request: Request) -> Principal:
    token = _bearer_from_header_or_cookie(authorization, request)

    # 1) Try first-party RS256 token via local JWKS
    try:
        local_jwks = await _fetch_json(f"{base_url}/.well-known/jwks.json")
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        # Find matching key in JWKS
        key = next(k for k in local_jwks.get("keys", []) if k.get("kid") == kid)
        claims = jwt.decode(
            token,
            key,  # python-jose accepts a JWK dict
            algorithms=["RS256"],
            options={"require_exp": True}
        )
        scopes = claims.get("scopes") or []
        return Principal(sub=claims.get("sub") or "", scopes=scopes, raw=claims)
    except Exception:
        pass  # Fall through to Okta

    # 2) Try Okta access token via Okta JWKS
    if not OKTA_METADATA_URL or not OKTA_ISSUER:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    try:
        meta = await _fetch_json(OKTA_METADATA_URL)
        jwks_uri = meta.get("jwks_uri")
        okta_jwks = await _fetch_json(jwks_uri)
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = next(k for k in okta_jwks.get("keys", []) if k.get("kid") == kid)
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=OKTA_AUDIENCE,
            issuer=OKTA_ISSUER,
            options={"require_exp": True, "require_aud": True, "require_iss": True}
        )
        scp = claims.get("scp") or []
        business_scopes = [s for s in scp if s.startswith(BUSINESS_PREFIXES)]
        scopes = business_scopes if business_scopes else ["orders:read"]
        return Principal(sub=claims.get("sub") or "", scopes=scopes, raw=claims)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Scope checker
def require_scopes(*needed: str):
    def _check(principal: Principal):
        missing = [s for s in needed if s not in (principal.scopes or [])]
        if missing:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing scopes: {missing}")
        return principal
    return _check
