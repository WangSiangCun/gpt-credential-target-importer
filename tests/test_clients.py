import json

import pytest

from credential_target_importer import (CredentialBundle, CpaTargetClient,
    Sub2ApiTargetClient, TargetImportError, build_cpa_json)


class Response:
    def __init__(self, data=None, status=200, text=None, headers=None):
        self.data = data
        self.status_code = status
        self.text = json.dumps(data) if text is None else text
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


class Http:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        assert kwargs["allow_redirects"] is False
        return self.responses.pop(0)


BUNDLE = CredentialBundle("a@example.com", "at", refresh_token="rt")


def test_cpa_client_uploads_exact_download_content():
    http = Http(Response({"status": "ok"}))
    result = CpaTargetClient("https://cpa.example", http, "secret").import_auth_file(BUNDLE)
    assert result == {"status": "ok"}
    args, kwargs = http.calls[0]
    assert args == ("POST", "https://cpa.example/v0/management/auth-files")
    filename, body, media_type = kwargs["files"]["file"]
    assert filename == "a_example.com.json" and media_type == "application/json"
    assert json.loads(body) == build_cpa_json(BUNDLE)
    assert kwargs["headers"]["Authorization"] == "Bearer secret"
    assert "Content-Type" not in kwargs["headers"]
    assert not hasattr(Sub2ApiTargetClient, "import_auth_file")


@pytest.mark.parametrize("suffix", ["", "/", "/api/v1", "/api/v1/admin"])
def test_sub2api_uses_real_route_auth_and_data_envelope(suffix):
    http = Http(Response({"code": 0, "data": {"account_created": 1, "account_failed": 0}}))
    result = Sub2ApiTargetClient("https://sub.example" + suffix, http, "key").import_account(BUNDLE, "team5x")
    args, kwargs = http.calls[0]
    assert args == ("POST", "https://sub.example/api/v1/admin/accounts/data")
    assert kwargs["headers"]["x-api-key"] == "key"
    assert "Authorization" not in kwargs["headers"]
    payload = kwargs["json_body"]
    assert payload["data"]["accounts"][0]["type"] == "oauth"
    assert payload["skip_default_group_bind"] is False
    assert "target" not in payload
    assert result["account_created"] == 1


@pytest.mark.parametrize("data", [
    {"code": 0, "data": {"account_created": 0, "account_failed": 1}},
    {"code": 0, "data": {"account_created": 0, "account_failed": 0}},
    {"code": 0, "data": {"account_created": 1, "account_failed": 1}},
    {"code": 0, "data": {"account_created": True, "account_failed": 0}},
    {"code": 0, "data": None}, {}, {"code": 403}])
def test_sub2api_http_200_does_not_hide_failed_or_unknown_import(data):
    with pytest.raises(TargetImportError):
        Sub2ApiTargetClient("https://sub.example", Http(Response(data))).import_account(BUNDLE)


@pytest.mark.parametrize("response", [Response({}, 204, text=""), Response({}),
    Response({"message": "no data"}), Response({"status": "unknown"})])
def test_empty_cpa_status_is_not_healthy(response):
    with pytest.raises(TargetImportError) as error:
        CpaTargetClient("https://cpa.example", Http(response)).status(BUNDLE.email, "team")
    assert error.value.code == "unknown_status"


@pytest.mark.parametrize("data,expected", [
    ({"unauthorized": "false", "quota_exhausted": "false"}, (False, False)),
    ({"unauthorized": "true"}, (True, False)),
    ({"status_code": 401}, (True, False)),
    ({"quota": {"used_up": True}}, (False, True)),
    ({"status": "ok"}, (False, False))])
def test_cpa_status_boolean_and_state_parsing(data, expected):
    result = CpaTargetClient("https://cpa.example", Http(Response(data))).status(BUNDLE.email, "team")
    assert (result.unauthorized, result.quota_exhausted) == expected


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_import_http_errors(status):
    with pytest.raises(TargetImportError) as error:
        CpaTargetClient("https://cpa.example", Http(Response({}, status))).import_auth_file(BUNDLE)
    assert error.value.uncertain == (status >= 500)


@pytest.mark.parametrize("response", [Response({"success": False}),
    Response({"error": "SECRET-REMOTE-TOKEN"}), Response(text="<html>error</html>")])
def test_bad_success_response_is_error_without_leaking_body(response):
    with pytest.raises(TargetImportError) as error:
        CpaTargetClient("https://cpa.example", Http(response)).import_auth_file(BUNDLE)
    assert "SECRET-REMOTE-TOKEN" not in str(error.value)


def test_same_origin_307_preserves_body_and_session():
    http = Http(Response(status=307, headers={"Location": "/canonical"}), Response({"status": "ok"}))
    CpaTargetClient("https://cpa.example", http).import_auth_file(BUNDLE)
    assert len(http.calls) == 2
    assert http.calls[1][0] == ("POST", "https://cpa.example/canonical")
    assert http.calls[0][1]["files"] == http.calls[1][1]["files"]


@pytest.mark.parametrize("location,status", [("https://other.example/upload", 307),
    ("http://cpa.example/upload", 308), ("/canonical", 302)])
def test_unsafe_redirect_not_followed(location, status):
    http = Http(Response(status=status, headers={"Location": location}))
    with pytest.raises(TargetImportError) as error:
        CpaTargetClient("https://cpa.example", http, "secret").import_auth_file(BUNDLE)
    assert error.value.code == "redirect" and len(http.calls) == 1


def test_bad_credentials_do_not_send_request():
    http = Http()
    with pytest.raises(ValueError):
        CpaTargetClient("https://cpa.example", http).import_auth_file(CredentialBundle("a@example.com", ""))
    assert not http.calls


@pytest.mark.parametrize("failure", [{"status": "error"}, {"code": 500},
    {"status_code": 503}, {"success": False}, {"status": "unknown"}])
def test_failed_query_overrides_stale_healthy_flags(failure):
    data = {"unauthorized": False, "quota_exhausted": False, **failure}
    with pytest.raises(TargetImportError) as error:
        CpaTargetClient("https://cpa.example", Http(Response(data))).status(BUNDLE.email, "team")
    assert error.value.code == "unknown_status"
