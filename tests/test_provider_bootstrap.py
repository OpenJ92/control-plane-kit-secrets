from __future__ import annotations

import json
import tempfile
import traceback
import unittest
from pathlib import Path

from control_plane_kit_secrets.auth import (
    ProviderAuthenticationError,
    ProviderAuthorizer,
    SecretUseDenied,
)
from control_plane_kit_secrets.bootstrap import (
    ProviderConfigurationError,
    load_provider_credentials,
)


class ProviderBootstrapTests(unittest.TestCase):
    def test_optional_fields_and_wildcards_keep_their_authority(self) -> None:
        empty = _load_document([])
        self.assertEqual(empty, ())
        with self.assertRaises(ProviderAuthenticationError):
            ProviderAuthorizer(empty).authenticate("Bearer fixture")
        for grants in (None, [], [{"action": "secret.resolve", "workspace_id": "*"}],
                       [{"action": "secret.resolve", "workspace_id": "*", "intents": []}],
                       [{"action": "secret.resolve", "workspace_id": "*", "intents": ["*"]}]):
            with self.subTest(case="omitted" if grants is None else len(grants)):
                item = {"subject": "client", "token": "fixture"}
                if grants is not None:
                    item["grants"] = grants
                credential, = _load_document([item])
                authorizer = ProviderAuthorizer((credential,))
                has_grant = bool(grants)
                permits_intent = has_grant and grants[0].get("intents", ["*"]) != []
                for intent in (None, "postgres.password"):
                    permitted = has_grant if intent is None else permits_intent
                    if permitted:
                        authorizer.require(credential, action="secret.resolve", workspace_id="any", intent=intent)
                    else:
                        with self.assertRaises(SecretUseDenied):
                            authorizer.require(credential, action="secret.resolve", workspace_id="any", intent=intent)

    def test_exact_text_repeated_grants_and_duplicate_subjects_remain_lawful(self) -> None:
        grant = {"action": "future.action", "workspace_id": " équipe ", "intents": ["future.intent", "future.intent"]}
        first, second = _load_document([
            {"subject": " même client ", "token": "internal space", "grants": [grant, grant]},
            {"subject": " même client ", "token": "x" * 4097},
        ])
        self.assertEqual(first.subject, " même client ")
        self.assertEqual(first.grants, (first.grants[0], first.grants[0]))
        self.assertEqual(first.grants[0].workspace_id, " équipe ")
        self.assertEqual(first.grants[0].intents, ("future.intent", "future.intent"))
        authorizer = ProviderAuthorizer((first, second))
        self.assertIs(authorizer.authenticate("Bearer internal space"), first)
        self.assertIs(authorizer.authenticate("Bearer " + "x" * 4097), second)
        authorizer.require(first, action="future.action", workspace_id=" équipe ", intent="future.intent")
        for credential in (first, second):
            with self.assertRaises(SecretUseDenied):
                authorizer.require(credential, action="secret.resolve", workspace_id="any", intent="postgres.password")

    def test_shapes_unknown_keys_missing_fields_and_duplicate_tokens_reject(self) -> None:
        valid = {"subject": "client", "token": "fixture"}
        grant = {"action": "secret.resolve", "workspace_id": "*"}
        invalid = [None, {}, "text", [None], [42], [[]],
                   [{"token": "fixture"}], [{"subject": "client"}],
                   [{**valid, "grant": []}], [{**valid, "grants": None}],
                   [{**valid, "grants": [None]}], [{**valid, "grants": [[]]}],
                   [{**valid, "grants": [{"action": "secret.resolve"}]}],
                   [{**valid, "grants": [{"workspace_id": "*"}]}],
                   [{**valid, "grants": [{**grant, "intent": []}]}],
                   [{**valid, "grants": [{**grant, "intents": None}]}],
                   [valid, valid], [valid, {**valid, "subject": "different", "grants": [grant]}]]
        for index, document in enumerate(invalid):
            with self.subTest(case=index):
                with self.assertRaises(ProviderConfigurationError):
                    _load_document(document)
        for payload in ('[{"subject":"a","subject":"b","token":"fixture"}]',
                        '[{"subject":"a","token":"fixture","grants":[{"action":"a","workspace_id":"*","intents":[],"intents":["*"]}]}]'):
            with self.assertRaises(ProviderConfigurationError):
                load_provider_credentials({"CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": payload})

    def test_text_fields_never_coerce_or_accept_blank_and_control_values(self) -> None:
        invalid = (0, True, None, [], {}, "", " \u2003 ", "a\x00b", "a\nb", "a\x7fb")
        for field in ("subject", "token", "action", "workspace_id", "intent"):
            for index, value in enumerate(invalid):
                with self.subTest(field=field, case=index):
                    grant = {"action": "secret.resolve", "workspace_id": "*", "intents": ["postgres.password"]}
                    item = {"subject": "client", "token": "fixture", "grants": [grant]}
                    if field in ("subject", "token"):
                        item[field] = value
                    elif field == "intent":
                        grant["intents"] = [value]
                    else:
                        grant[field] = value
                    with self.assertRaises(ProviderConfigurationError):
                        _load_document([item])
        for index, token in enumerate((" fixture", "fixture ", "caf\u00e9", "a\tb")):
            with self.subTest(token_case=index):
                with self.assertRaises(ProviderConfigurationError):
                    _load_document([{"subject": "client", "token": token}])

    def test_both_sources_enforce_utf8_byte_boundaries(self) -> None:
        # A multibyte subject distinguishes encoded-byte limits from character counts.
        payload = json.dumps([{"subject": "\u00e9", "token": "fixture"}], ensure_ascii=False)
        payload += " " * (65536 - len(payload.encode("utf-8")))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            for extra in ("", " "):
                for source in ("file", "development"):
                    with self.subTest(extra_bytes=len(extra), source=source):
                        bounded = payload + extra
                        path.write_text(bounded, encoding="utf-8")
                        path.chmod(0o400)
                        environment = ({"CPK_SECRETS_CREDENTIALS_FILE": str(path)} if source == "file" else
                                       {"CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": bounded})
                        if extra:
                            with self.assertRaises(ProviderConfigurationError):
                                load_provider_credentials(environment)
                        else:
                            self.assertEqual(load_provider_credentials(environment)[0].subject, "\u00e9")
                        path.chmod(0o600)

    def test_source_selection_preserves_empty_value_asymmetry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            path.write_text(_credentials_json(), encoding="utf-8")
            path.chmod(0o600)
            loaded = load_provider_credentials({"CPK_SECRETS_CREDENTIALS_FILE": str(path),
                                               "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": ""})
            self.assertEqual(len(loaded), 1)
            for file_value, dev_value in (("", _credentials_json()), ("", ""), (str(path), _credentials_json())):
                with self.assertRaises(ProviderConfigurationError):
                    load_provider_credentials({"CPK_SECRETS_CREDENTIALS_FILE": file_value,
                                               "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": dev_value})

    def test_configuration_tracebacks_redact_source_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "private-path-marker")
            invalid_path = Path(directory, "private-invalid-utf8")
            invalid_path.write_bytes(b"private-document-marker\xff")
            invalid_path.chmod(0o600)
            environments = (
                {"CPK_SECRETS_CREDENTIALS_FILE": str(path)},
                {"CPK_SECRETS_CREDENTIALS_FILE": str(invalid_path)},
                {"CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": "private-document-marker"},
                {"CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": "\ud800private-document-marker"},
            )
            for index, environment in enumerate(environments):
                with self.subTest(case=index):
                    try:
                        load_provider_credentials(environment)
                    except ProviderConfigurationError as error:
                        rendered = "".join(traceback.format_exception(error))
                        self.assertEqual(str(error), "secret provider configuration is invalid")
                        self.assertLess(len(rendered), 8192)
                        for forbidden in (str(path), str(invalid_path), "private-document-marker"):
                            self.assertFalse(forbidden in rendered, "configuration detail leaked")
                    else:
                        self.fail("invalid credential source accepted")

    def test_production_credentials_load_from_owner_only_absolute_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "provider-credentials.json")
            path.write_text(_credentials_json(), encoding="utf-8")
            path.chmod(0o600)

            credentials = load_provider_credentials(
                {"CPK_SECRETS_CREDENTIALS_FILE": str(path)}
            )

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].subject, "cpk-server")
            self.assertNotIn("provider-bootstrap-token", repr(credentials))

    def test_production_credentials_reject_unsafe_or_ambiguous_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            credentials = base / "provider-credentials.json"
            credentials.write_text(_credentials_json(), encoding="utf-8")
            credentials.chmod(0o644)
            symlink = base / "credentials-link.json"
            symlink.symlink_to(credentials)

            invalid = (
                {},
                {"CPK_SECRETS_CREDENTIALS_FILE": "relative.json"},
                {"CPK_SECRETS_CREDENTIALS_FILE": str(credentials)},
                {"CPK_SECRETS_CREDENTIALS_FILE": str(symlink)},
                {
                    "CPK_SECRETS_CREDENTIALS_FILE": str(credentials),
                    "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": _credentials_json(),
                },
            )
            for environment in invalid:
                with self.subTest(environment_keys=tuple(environment)):
                    with self.assertRaises(ProviderConfigurationError) as context:
                        load_provider_credentials(environment)
                    self.assertNotIn(
                        "provider-bootstrap-token",
                        str(context.exception),
                    )

    def test_development_json_is_explicit_and_duplicate_keys_fail_closed(self) -> None:
        credentials = load_provider_credentials(
            {
                "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": _credentials_json(),
            }
        )
        self.assertEqual(credentials[0].subject, "cpk-server")

        with self.assertRaises(ProviderConfigurationError):
            load_provider_credentials(
                {
                    "CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": (
                        '[{"subject":"a","subject":"b","token":"token","grants":[]}]'
                    ),
                }
            )


def _load_document(document: object):
    return load_provider_credentials({"CPK_SECRETS_DEVELOPMENT_CREDENTIALS_JSON": json.dumps(document)})


def _credentials_json() -> str:
    return json.dumps(
        [
            {
                "subject": "cpk-server",
                "token": "provider-bootstrap-token",
                "grants": [
                    {
                        "action": "secret.resolve",
                        "workspace_id": "*",
                        "intents": ["postgres.password"],
                    }
                ],
            }
        ],
        separators=(",", ":"),
        sort_keys=True,
    )


if __name__ == "__main__":
    unittest.main()
