from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialBundle:
    email: str
    access_token: str
    session_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    account_id: str = ""

    def validate(self, required=("email", "access_token")) -> None:
        # Presence validation only; authorization/refresh belongs to the caller.
        for name in required:
            value = getattr(self, name, None)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"缺少凭证字段：{name}")
        for name in ("email", "access_token", "session_token", "refresh_token", "id_token", "account_id"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"凭证字段必须是字符串：{name}")
        if any(ch in self.email for ch in (chr(13), chr(10), "/", chr(92))):
            raise ValueError("邮箱格式无效")

    def as_dict(self) -> dict:
        self.validate()
        result = {name: getattr(self, name).strip() for name in
                  ("email", "access_token", "session_token", "refresh_token")}
        for name in ("id_token", "account_id"):
            if getattr(self, name).strip():
                result[name] = getattr(self, name).strip()
        return result


@dataclass(frozen=True)
class TargetStatus:
    email: str
    target: str
    unauthorized: bool
    quota_exhausted: bool
    message: str = ""
    raw: dict | None = None
