from __future__ import annotations

import json
from urllib.parse import urljoin

from .models import CredentialBundle, TargetStatus
from .formats import build_cpa_auth_file


class TargetImportError(RuntimeError):
    def __init__(self, code: str, message: str, *, uncertain: bool = False):
        super().__init__(message)
        self.code = code
        self.uncertain = uncertain


class CpaTargetClient:
    """CPA adapter. The HTTP session is injected to keep proxy ownership local."""

    def __init__(self, base_url: str, http, api_token: str = ""):
        self.base_url = base_url.strip().rstrip("/")
        self.http = http
        self.api_token = api_token.strip()
        if not self.base_url:
            raise TargetImportError("config", "请先配置 CPA 地址")

    def _headers(self) -> dict:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = "Bearer " + self.api_token
        return headers

    @staticmethod
    def _json(response) -> dict:
        if response.status_code == 204 or not (response.text or "").strip():
            return {}
        try:
            data = response.json()
        except ValueError:
            raise TargetImportError("invalid_response", "CPA 返回不是 JSON") from None
        if not isinstance(data, dict):
            raise TargetImportError("invalid_response", "CPA 返回结构异常")
        return data

    def status(self, email: str, target: str) -> TargetStatus:
        response = self.http.request("GET", urljoin(self.base_url + "/", "api/account-status"),
                                     headers=self._headers(), params={"email": email, "target": target})
        if response.status_code == 401:
            raise TargetImportError("http_401", "CPA 管理接口认证失败")
        if response.status_code not in (200, 204):
            raise TargetImportError("http_status", f"CPA 状态查询 HTTP {response.status_code}")
        data = self._json(response)
        code = data.get("status_code") or data.get("account_status_code") or data.get("http_status")
        state = str(data.get("status") or data.get("state") or "").lower()
        quota = data.get("quota") if isinstance(data.get("quota"), dict) else {}
        unauthorized = bool(data.get("unauthorized") or data.get("is_401")) or str(code) == "401"
        exhausted = bool(data.get("quota_exhausted") or data.get("quota_used_up"))
        exhausted = exhausted or state in {"quota_exhausted", "exhausted", "depleted"}
        exhausted = exhausted or bool(quota.get("exhausted") or quota.get("used_up"))
        return TargetStatus(email, target, unauthorized, exhausted,
                            str(data.get("message") or data.get("detail") or ""), data)

    def import_account(self, credentials: CredentialBundle, target: str) -> dict:
        payload = credentials.as_dict()
        payload["target"] = target
        response = self.http.request("POST", urljoin(self.base_url + "/", "api/accounts/import"),
                                     headers=self._headers(), json_body=payload)
        if response.status_code not in (200, 201, 204):
            raise TargetImportError("import_failed", f"CPA 导入 HTTP {response.status_code}", uncertain=True)
        return self._json(response)


class Sub2ApiTargetClient:
    """Sub2API credential delivery adapter with an injected HTTP session."""

    def __init__(self, base_url: str, http, api_token: str = ""):
        self.base_url = base_url.strip().rstrip("/")
        self.http = http
        self.api_token = api_token.strip()
        if not self.base_url:
            raise TargetImportError("config", "请先配置 Sub2API 地址")

    def import_account(self, credentials: CredentialBundle, target: str = "") -> dict:
        payload = {**credentials.as_dict(), "target": target}
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = "Bearer " + self.api_token
            headers["x-api-key"] = self.api_token
        response = self.http.request("POST", urljoin(self.base_url + "/", "api/accounts/import"),
                                     headers=headers, json_body=payload)
        if response.status_code not in (200, 201, 204):
            raise TargetImportError("import_failed", f"Sub2API 导入 HTTP {response.status_code}", uncertain=True)
        return CpaTargetClient._json(response)

    def import_auth_file(self, credentials: CredentialBundle, plan_type: str = "team") -> dict:
        """Upload a CPA-compatible auth file through the management API."""
        payload = build_cpa_auth_file(credentials, plan_type)
        filename = credentials.email.replace("@", "_") + ".json"
        response = self.http.request(
            "POST", urljoin(self.base_url + "/", "v0/management/auth-files"),
            headers={"Accept": "application/json",
                     "Authorization": "Bearer " + self.api_token,
                     "X-Management-Key": self.api_token},
            files={"file": (filename, json.dumps(payload, ensure_ascii=False).encode(), "application/json")},
        )
        if response.status_code not in (200, 201, 204):
            raise TargetImportError("import_failed", f"CPA 导入 HTTP {response.status_code}", uncertain=True)
        return self._json(response)
