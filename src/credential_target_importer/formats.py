import base64
import json
from datetime import datetime, timezone

from .models import CredentialBundle


def _claims(token: str) -> dict:
    # Metadata extraction, not JWT signature validation.
    try:
        part = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return value if isinstance(value, dict) else {}
    except (ValueError, IndexError, UnicodeError):
        return {}


def _metadata(credentials: CredentialBundle) -> dict:
    credentials.validate()
    at = _claims(credentials.access_token.strip())
    identity = _claims(credentials.id_token.strip())
    result = {}
    for claims in (identity, at):
        auth = claims.get("https://api.openai.com/auth")
        auth = auth if isinstance(auth, dict) else {}
        profile = claims.get("https://api.openai.com/profile")
        profile = profile if isinstance(profile, dict) else {}
        email = claims.get("email") or profile.get("email")
        if email and str(email).strip().lower() != credentials.email.strip().lower():
            raise ValueError("凭证邮箱与导出账号不一致，请重新获取正确账号的凭证")
        account_id = str(auth.get("chatgpt_account_id") or auth.get("account_id") or "").strip()
        if account_id:
            if result.get("account_id") and result["account_id"] != account_id:
                raise ValueError("AT 与 ID token 的工作区不一致，请重新获取凭证")
            result["account_id"] = account_id
        for source, dest in (("chatgpt_plan_type", "plan_type"),
                             ("chatgpt_user_id", "chatgpt_user_id"),
                             ("organization_id", "organization_id")):
            if auth.get(source):
                result[dest] = str(auth[source]).strip()
    expected = credentials.account_id.strip()
    if expected and result.get("account_id") != expected:
        raise ValueError("凭证工作区与目标工作区不一致或未确认，请重新获取凭证")
    if at.get("client_id"):
        result["client_id"] = str(at["client_id"])
    if at.get("exp") is not None:
        try:
            expiry = datetime.fromtimestamp(float(at["exp"]), timezone.utc)
        except (ValueError, TypeError, OverflowError, OSError):
            raise ValueError("AT 到期时间格式无效") from None
        result["expired"] = expiry.isoformat()
        result["expires_at"] = int(expiry.timestamp())
    return result


def build_cpa_auth_file(credentials: CredentialBundle, plan_type: str = "") -> dict:
    """CPA auth-file. Legacy plan_type is accepted but never overrides token claims."""
    metadata = _metadata(credentials)
    payload = {"type": "codex", "email": credentials.email.strip(),
               "access_token": credentials.access_token.strip(),
               "refresh_token": credentials.refresh_token.strip(),
               "account_id": metadata.get("account_id", ""),
               "expired": metadata.get("expired", ""), "last_refresh": ""}
    if credentials.id_token.strip():
        payload["id_token"] = credentials.id_token.strip()
    if metadata.get("plan_type"):
        payload["plan_type"] = metadata["plan_type"]
        payload["chatgpt_plan_type"] = metadata["plan_type"]
    if metadata.get("client_id"):
        payload["client_id"] = metadata["client_id"]
    return payload


def build_cpa_json(credentials: CredentialBundle) -> dict:
    return build_cpa_auth_file(credentials)


def build_sub2api_json(credentials: CredentialBundle) -> dict:
    """Sub2API admin data-file v1; direct upload wraps this in {data: ...}."""
    metadata = _metadata(credentials)
    values = {k: v for k, v in credentials.as_dict().items() if v and k != "account_id"}
    for key in ("plan_type", "client_id", "chatgpt_user_id", "organization_id", "expires_at"):
        if key in metadata:
            values[key] = metadata[key]
    if metadata.get("account_id"):
        values["chatgpt_account_id"] = metadata["account_id"]
    return {"type": "sub2api-data", "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(), "proxies": [],
            "accounts": [{"name": credentials.email.strip(), "platform": "openai",
                          "type": "oauth", "credentials": values,
                          "concurrency": 1, "priority": 0}]}
