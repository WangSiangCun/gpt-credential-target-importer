from credential_target_importer import CredentialBundle, build_cpa_json, build_sub2api_json


def test_formats():
    bundle = CredentialBundle("a@example.com", "at", "session", "rt")
    assert build_cpa_json(bundle)["email"] == "a@example.com"
    assert build_sub2api_json(bundle)["credentials"]["refresh_token"] == "rt"
