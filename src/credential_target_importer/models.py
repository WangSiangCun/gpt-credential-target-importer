from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialBundle:
    email: str
    access_token: str
    session_token: str
    refresh_token: str

    def validate(self) -> None:
        if not all((self.email.strip(), self.access_token.strip(),
                    self.session_token.strip(), self.refresh_token.strip())):
            raise ValueError("email、AT、session、RT 必须完整")

    def as_dict(self) -> dict:
        self.validate()
        return {"email": self.email, "access_token": self.access_token,
                "session_token": self.session_token, "refresh_token": self.refresh_token}


@dataclass(frozen=True)
class TargetStatus:
    email: str
    target: str
    unauthorized: bool
    quota_exhausted: bool
    message: str = ""
    raw: dict | None = None
