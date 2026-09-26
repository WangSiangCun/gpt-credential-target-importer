import base64
import json

import pytest

from credential_target_importer import (CredentialBundle, build_cpa_json,
                                       build_sub2api_json, build_cpa_auth_file)


def token(claims):
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "header." + encoded + ".signature"


def test_cpa_download_matches_upload_and_does_not_fake_id_or_plan():
    bundle = CredentialBundle("a@example.com", "at")
    assert build_cpa_json(bundle) == build_cpa_auth_file(bundle, "team")
    assert build_cpa_json(bundle)["type"] == "codex"
    assert "id_token" not in build_cpa_json(bundle)
    assert "plan_type" not in build_cpa_json(bundle)


@pytest.mark.parametrize("plan", ["free", "team", "self_serve_business_prolite"])
def test_real_metadata_not_overridden_by_seat_label(plan):
    at = token({"https://api.openai.com/auth": {"chatgpt_account_id": "workspace-1",
                "chatgpt_plan_type": plan}, "exp": 1900000000, "client_id": "client-1"})
    bundle = CredentialBundle("a@example.com", at, refresh_token="rt", account_id="workspace-1")
    payload = build_cpa_auth_file(bundle, "team5x")
    assert payload["plan_type"] == plan
    assert payload["account_id"] == "workspace-1"
    assert payload["expired"] and payload["client_id"] == "client-1"
    sub = build_sub2api_json(bundle)["accounts"][0]["credentials"]
    assert sub["chatgpt_account_id"] == "workspace-1"
    assert sub["plan_type"] == plan
    assert sub["expires_at"] == 1900000000


def test_real_id_token_preserved():
    bundle = CredentialBundle("a@example.com", "at", id_token="real-id")
    assert build_cpa_json(bundle)["id_token"] == "real-id"
    assert build_sub2api_json(bundle)["accounts"][0]["credentials"]["id_token"] == "real-id"


@pytest.mark.parametrize("claims", [{"email": "other@example.com"},
    {"https://api.openai.com/profile": {"email": "other@example.com"}}])
def test_mismatched_email_rejected(claims):
    with pytest.raises(ValueError, match="邮箱"):
        build_cpa_json(CredentialBundle("a@example.com", token(claims)))


@pytest.mark.parametrize("at", ["opaque", token({"https://api.openai.com/auth": {"chatgpt_account_id": "other"}})])
def test_expected_workspace_must_match(at):
    with pytest.raises(ValueError, match="工作区"):
        build_cpa_json(CredentialBundle("a@example.com", at, account_id="expected"))


def test_id_token_and_access_token_workspace_mismatch():
    def at(wid):
        return token({"https://api.openai.com/auth": {"chatgpt_account_id": wid}})
    with pytest.raises(ValueError, match="工作区"):
        build_cpa_json(CredentialBundle("a@example.com", at("a"), id_token=at("b")))


@pytest.mark.parametrize("claims", [[], None, {"https://api.openai.com/auth": []}])
def test_unusual_claim_shapes_do_not_crash(claims):
    assert build_cpa_json(CredentialBundle("a@example.com", token(claims)))["type"] == "codex"


@pytest.mark.parametrize("expiry", ["bad", float("inf"), {}, 1e99])
def test_invalid_expiry_is_validation_error(expiry):
    with pytest.raises(ValueError, match="到期时间"):
        build_cpa_json(CredentialBundle("a@example.com", token({"exp": expiry})))


@pytest.mark.parametrize("builder", [build_cpa_json, build_cpa_auth_file, build_sub2api_json])
def test_access_token_required_but_session_and_rt_optional(builder):
    assert builder(CredentialBundle("a@example.com", "at"))
    with pytest.raises(ValueError, match="access_token"):
        builder(CredentialBundle("a@example.com", " "))


def test_sub2api_matches_data_import_contract():
    data = build_sub2api_json(CredentialBundle("a@example.com", "at", "session", "rt"))
    assert data["type"] == "sub2api-data" and data["version"] == 1
    assert data["proxies"] == [] and data["exported_at"]
    account, = data["accounts"]
    assert account["platform"] == "openai" and account["type"] == "oauth"
    assert account["concurrency"] > 0 and account["priority"] >= 0
    assert account["credentials"]["refresh_token"] == "rt"


def test_path_in_email_rejected():
    with pytest.raises(ValueError, match="邮箱"):
        build_cpa_json(CredentialBundle("../a@example.com", "at"))
