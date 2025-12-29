
# main.py
import secrets, base64, hashlib, urllib.parse
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()

# Ensure cookie survives the Okta -> Render redirect
app.add_middleware(
    SessionMiddleware,
    secret_key="change-me",
    same_site="lax",      # try "lax"; if your browser still drops the cookie, switch to "none"
    https_only=True,      # Render uses HTTPS
    max_age=600
)

OKTA_ISSUER = "https://integrator-4349888.okta.com/oauth2/default"
CLIENT_ID = "0oayp9nuc0ZHdTAey697"
REDIRECT_URI = "https://fastapiweb-yex7.onrender.com/callback"  # must match Okta app setting EXACTLY
SCOPES = "openid profile email"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

@app.get("/authorize")
async def authorize(request: Request):
    # Generate and store state + PKCE
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    code_verifier = b64url(secrets.token_bytes(32))
    code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())

    request.session["oidc_state"] = state
    request.session["pkce_verifier"] = code_verifier

    # Build the ONE-LINE authorize URL (no comments, no &amp;)
    q = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{OKTA_ISSUER}/v1/authorize?{urllib.parse.urlencode(q)}"
    return RedirectResponse(url, status_code=302)

@app.get("/callback")
async def callback(request: Request):
    returned_state = request.query_params.get("state")
    stored_state = request.session.get("oidc_state")
    if not stored_state or returned_state != stored_state:
        return {"detail": "Invalid or expired state"}

    # OPTIONAL: token exchange (Public client + PKCE: no secret)
    # Now use request.session["pkce_verifier"] to call /v1/token
    return {"detail": "State OK — ready to exchange code"}
