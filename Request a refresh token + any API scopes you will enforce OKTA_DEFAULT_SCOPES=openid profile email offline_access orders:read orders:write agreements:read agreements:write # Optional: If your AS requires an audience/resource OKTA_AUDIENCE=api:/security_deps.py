
# security_deps.py
import time, base64, logging, os, httpx
from typing import Optional, Dict, Any, List
from fastapi import HTTPException, status, Depends
from jose import jwt, JWTError

OKTA_ISSUER = (os.getenv("OKTA_ISSUER") or "").strip()
OKTA_METADATA_URL = (os.getenv("OKTA_METADATA_URL") or "").strip()

# Minimal in-memory caches
_meta_cache: Optional[Dict[str, Any]] = None
_jwks_cache_okta: Optional[Dict[str, Any]] = None
_jwks_cache_okta_exp: float = 0
_jwks_cache_local: Optional[Dict[str, Any]] = None
_jwks_cache_local_exp: float = 0

JWKS_TTL = 300  # 5 minutes

async def _get_okta_meta() -> Dict[str, Any]:
    global _meta_cache
    if _meta_cache:
        return _meta_cache
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(OKTA_METADATA_URL)
        r.raise_for_status()
        _meta_cache = r.json()
        return _meta_cache

async def _get_okta_jwks() -> Dict[str, Any]:
    global _jwks_cache_okta, _jwks_cache_okta_exp
    now = time.time()
    if _jwks_cache_okta and now < _jwks_cache_okta_exp:
        return _jwks_cache_okta
    meta = await _get_okta_meta()
    jwks_uri = meta.get("jwks_uri")
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(jwks_uri)
        r.raise_for_status()
        _jwks_cache_okta = r.json()
        _jwks_cache_okta_exp = now + JWKS_TTL
        return _jwks_cache_okta

async def _get_local_jwks(base_url: str) -> Dict[str, Any]:
    """Fetch your API's JWKS for local RS256 verification."""
    global _jwks_cache_local, _jwks_cache_local_exp
    now = time.time()
    if _jwks_cache_local and now < _jwks_cache_local_exp:
        return _jwks_cache_local
    url = f"{base_url}/.well-known/jwks.json"
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get(url)
        r.raise_for_status()
        _jwks_cache_local = r.json()
        _jwks_cache_local_exp = now + JWKS_TTL
        return _jwks_cache_local

class Principal:
    def __init__(self, sub: str, scopes: List[str], roles: List[str], raw: Dict[str, Any]):
        self.sub = sub
        self.scopes = scopes
        self.roles = roles
        self.raw = raw

async def require_auth(authorization: Optional[str] = None, base_url: Optional[str] = None) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        header = jwt.get_unverified_header(token)
        claims_unverified = jwt.get_unverified_claims(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token header")

    iss = claims_unverified.get("iss")
    kid = header.get("kid")

    jwk = None
    if iss and OKTA_ISSUER and iss.rstrip("/") == OKTA_ISSUER.rstrip("/"):
        # Okta token path
        jwks = await _get_okta_jwks()
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                jwk = k
                break
        audience = claims_unverified.get("aud")
        try:
            claims = jwt.decode(
                token,
                jwk,  # python-jose accepts JWK dict
                algorithms=["RS256"],
                audience=audience or os.getenv("OKTA_AUDIENCE"),
                issuer=OKTA_ISSUER,
                options={"require_exp": True, "require_iat": True, "require_iss": True}
            )
        except JWTError as e:
            raise HTTPException(status_code=401, detail=f"Okta token verification failed: {str(e)}")
        scopes = claims.get("scp", [])
        roles = claims.get("roles", claims.get("groups", [])) or []
        return Principal(sub=claims.get("sub", ""), scopes=scopes, roles=roles, raw=claims)
    else:
        # Your API token path (RS256 signed by your keys)
        if not base_url:
            # Base URL can be injected in FastAPI dependency via Request
            raise HTTPException(status_code=500, detail="Base URL not set for JWKS retrieval")
        jwks = await _get_local_jwks(base_url)
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                jwk = k
                break
        if not jwk:
            raise HTTPException(status_code=401, detail="Unknown key id")
        try:
            claims = jwt.decode(
                token, jwk, algorithms=["RS256"],
                options={"require_exp": True}
            )
        except JWTError as e:
            raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")
        scopes = claims.get("scopes", [])
        roles = claims.get("roles", [])
        return Principal(sub=claims.get("sub", ""), scopes=scopes, roles=roles, raw=claims)

def require_scopes(*required: str):
    async def _dep(principal: Principal = Depends(require_auth)):
        s = set(principal.scopes or [])
        if not set(required).issubset(s):
            raise HTTPException(status_code=403, detail="insufficient_scope")
        return principal
    return _dep
