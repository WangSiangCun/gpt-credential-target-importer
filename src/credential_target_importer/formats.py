import base64
import json
from datetime import datetime, timezone

from .models import CredentialBundle


def _claims(token: str) -> dict:
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return {}


def build_cpa_auth_file(credentials: CredentialBundle, plan_type: str = "team") -> dict:
    """Build the CLIProxyAPI CPA auth-file payload."""
    credentials.validate()
    claims = _claims(credentials.access_token)
    auth = claims.get("https://api.openai.com/auth") if isinstance(claims, dict) else {}
    auth = auth if isinstance(auth, dict) else {}
    plan = str(auth.get("chatgpt_plan_type") or plan_type or "team").strip().lower()
    account_id = str(auth.get("chatgpt_account_id") or auth.get("account_id") or "")
    payload = {"type": "codex", "email": credentials.email, "expired": "",
               "id_token": credentials.access_token, "account_id": account_id,
               "access_token": credentials.access_token, "last_refresh": "",
               "refresh_token": credentials.refresh_token, "plan_type": plan,
               "chatgpt_plan_type": plan}
    if claims.get("client_id"):
        payload["client_id"] = str(claims["client_id"])
    if claims.get("exp"):
        payload["expired"] = datetime.fromtimestamp(float(claims["exp"]), timezone.utc).isoformat()
    return payload


def build_cpa_json(credentials: CredentialBundle) -> dict:
    return credentials.as_dict()


def build_sub2api_json(credentials: CredentialBundle) -> dict:
    credentials.validate()
    return {"type": "openai", "name": credentials.email,
            "credentials": credentials.as_dict()}
