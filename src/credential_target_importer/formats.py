from .models import CredentialBundle


def build_cpa_json(credentials: CredentialBundle) -> dict:
    return credentials.as_dict()


def build_sub2api_json(credentials: CredentialBundle) -> dict:
    credentials.validate()
    return {"type": "openai", "name": credentials.email,
            "credentials": credentials.as_dict()}
