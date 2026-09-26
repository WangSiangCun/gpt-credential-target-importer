from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from .models import CredentialBundle, TargetStatus
from .formats import build_cpa_auth_file, build_sub2api_json


class TargetImportError(RuntimeError):
    def __init__(self, code: str, message: str, *, uncertain: bool = False):
        super().__init__(message)
        self.code = code
        self.uncertain = uncertain


def _origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise TargetImportError("config", "交付地址必须是有效的 HTTP/HTTPS 地址，不应包含账密")
    try:
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise TargetImportError("config", "交付地址端口无效") from None


def _request(http, method, url, **kwargs):
    # Explicitly override transport defaults. Never forward credentials cross-origin.
    origin = _origin(url)
    for _ in range(4):
        response = http.request(method, url, allow_redirects=False, **kwargs)
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        location = (getattr(response, "headers", {}) or {}).get("Location")
        if not location:
            raise TargetImportError("redirect", "目标重定向缺少 Location，请检查交付地址")
        next_url = urljoin(url, location)
        if _origin(next_url) != origin:
            raise TargetImportError("redirect", "目标重定向改变来源，请直接配置最终交付地址")
        if method != "GET" and response.status_code not in (307, 308):
            raise TargetImportError("redirect", "目标重定向会改变上传方法，请配置最终交付地址")
        url = next_url
    raise TargetImportError("redirect", "目标重定向次数过多")


def _json(response) -> dict:
    if response.status_code == 204 or not (response.text or "").strip():
        return {}
    try:
        data = response.json()
    except ValueError:
        raise TargetImportError("invalid_response", "目标返回不是 JSON") from None
    if not isinstance(data, dict):
        raise TargetImportError("invalid_response", "目标返回结构异常")
    return data


def _import_result(response, label):
    if response.status_code not in (200, 201, 204):
        raise TargetImportError("import_failed", f"{label} 导入 HTTP {response.status_code}",
                                uncertain=response.status_code >= 500)
    try:
        data = _json(response)
    except TargetImportError as exc:
        raise TargetImportError(exc.code, str(exc), uncertain=True) from None
    if (data.get("success") is False or data.get("error") or
            str(data.get("status", "")).lower() in ("error", "failed") or
            ("code" in data and str(data["code"]) not in ("0", "200", "201", "204"))):
        raise TargetImportError("import_failed", f"{label} 返回导入失败，请检查目标服务记录", uncertain=True)
    return data


def _flag(data, *names):
    result = None
    for name in names:
        if name not in data or data[name] is None:
            continue
        value = data[name]
        if value is True or value == 1 or isinstance(value, str) and value.lower() in ("true", "1"):
            result = True
        elif value is False or value == 0 or isinstance(value, str) and value.lower() in ("false", "0"):
            if result is None:
                result = False
        else:
            raise TargetImportError("invalid_response", "目标状态字段不是布尔值")
    return result


class CpaTargetClient:
    """CPA adapter using an injected proxy/fingerprint transport."""

    def __init__(self, base_url: str, http, api_token: str = ""):
        self.base_url = base_url.strip().rstrip("/")
        _origin(self.base_url)
        self.http = http
        self.api_token = api_token.strip()

    def _headers(self):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = "Bearer " + self.api_token
        return headers

    _json = staticmethod(_json)

    def status(self, email: str, target: str) -> TargetStatus:
        # Optional legacy status gateway, not the CLIProxyAPI management API.
        response = _request(self.http, "GET", urljoin(self.base_url + "/", "api/account-status"),
                            headers=self._headers(), params={"email": email, "target": target})
        if response.status_code == 401:
            raise TargetImportError("http_401", "CPA 管理接口认证失败")
        if response.status_code not in (200, 204):
            raise TargetImportError("http_status", f"CPA 状态查询 HTTP {response.status_code}")
        data = _json(response)
        code = str(data.get("status_code") or data.get("account_status_code") or data.get("http_status") or "")
        state = str(data.get("status") or data.get("state") or "").lower()
        quota = data.get("quota") if isinstance(data.get("quota"), dict) else {}
        unauthorized = _flag(data, "unauthorized", "is_401")
        exhausted = _flag(data, "quota_exhausted", "quota_used_up")
        nested = _flag(quota, "exhausted", "used_up")
        unauthorized = unauthorized is True or code == "401" or state in ("unauthorized", "invalid_token")
        exhausted_value = exhausted is True or nested is True or state in ("quota_exhausted", "exhausted", "depleted")
        normal = (state in ("ok", "healthy", "normal", "active", "ready") or code == "200" or
                  (_flag(data, "unauthorized", "is_401") is False and (exhausted is False or nested is False)))
        # A failed query is not a healthy account, even with stale false flags.
        query_failed = (data.get("error") or data.get("success") is False or
                        ("code" in data and str(data["code"]) not in ("0", "200")) or
                        state in ("error", "failed", "unknown", "pending") or
                        code not in ("", "200", "401"))
        if query_failed or not (unauthorized or exhausted_value or normal):
            raise TargetImportError("unknown_status", "CPA 未返回明确账号状态，本次检测结果为未知")
        return TargetStatus(email, target, unauthorized, exhausted_value,
                            str(data.get("message") or data.get("detail") or ""), data)

    def import_account(self, credentials: CredentialBundle, target: str) -> dict:
        """Legacy gateway API, retained only for explicit gateway callers."""
        payload = {**credentials.as_dict(), "target": target}
        response = _request(self.http, "POST", urljoin(self.base_url + "/", "api/accounts/import"),
                            headers=self._headers(), json_body=payload)
        return _import_result(response, "CPA")

    def import_auth_file(self, credentials: CredentialBundle, plan_type: str = "") -> dict:
        payload = build_cpa_auth_file(credentials, plan_type)
        filename = credentials.email.strip().replace("@", "_") + ".json"
        headers = {"Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = "Bearer " + self.api_token
        response = _request(self.http, "POST", urljoin(self.base_url + "/", "v0/management/auth-files"),
                            headers=headers, files={"file": (filename, json.dumps(payload, ensure_ascii=False).encode(), "application/json")})
        return _import_result(response, "CPA")


class Sub2ApiTargetClient:
    """Sub2API admin data-import API; api_token is an admin API key."""

    def __init__(self, base_url: str, http, api_token: str = ""):
        self.base_url = base_url.strip().rstrip("/")
        _origin(self.base_url)
        self.http = http
        self.api_token = api_token.strip()

    def import_account(self, credentials: CredentialBundle, target: str = "") -> dict:
        # target is a legacy seat label, NOT a subscription or Sub2API group ID.
        payload = {"data": build_sub2api_json(credentials), "skip_default_group_bind": False}
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_token:
            headers["x-api-key"] = self.api_token
        base = self.base_url
        for suffix in ("/api/v1/admin", "/api/v1"):
            if base.endswith(suffix):
                base = base[:-len(suffix)]
                break
        response = _request(self.http, "POST", base + "/api/v1/admin/accounts/data",
                            headers=headers, json_body=payload)
        envelope = _import_result(response, "Sub2API")
        result = envelope.get("data", envelope)
        if not isinstance(result, dict):
            raise TargetImportError("invalid_response", "Sub2API 未返回导入结果", uncertain=True)
        created, failed = result.get("account_created"), result.get("account_failed")
        if type(created) is not int or type(failed) is not int or created < 0 or failed < 0:
            raise TargetImportError("invalid_response", "Sub2API 未返回有效的账号导入计数", uncertain=True)
        if failed or result.get("errors") or result.get("proxy_failed") or created != 1:
            raise TargetImportError("import_failed", f"Sub2API 导入结果：成功 {created}，失败 {failed}，请检查目标服务记录", uncertain=created > 0)
        return result
