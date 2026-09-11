Source: [src/control_plane_kit_secrets/auth.py](../../../../src/control_plane_kit_secrets/auth.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This owner separates provider-client authentication from scoped secret use. Bearer-token comparison selects a configured credential; require then checks its action, workspace and optional intent grants. It does not know CPK plan approval, runtime ownership or resource identity.

Action matching is exact. Workspace and intent may carry explicit wildcard grants; an omitted intent in a require call is different from an empty allowed-intent list. [bootstrap.py](../../../../src/control_plane_kit_secrets/bootstrap.py) validates the configured credential document. These small value classes are not a substitute for that parser.

Call authenticate before require: require accepts the supplied credential object and does not itself prove membership in this authorizer. [api.py](../../../../src/control_plane_kit_secrets/api.py) owns request ordering, endpoint action selection and provider audit composition. Do not infer permission to execute a deployment merely from permission to resolve a secret.

Credential/token repr suppression and fixed authentication/denial messages avoid normal accidental disclosure; they do not authorize recording objects or headers. No raw or secret-derived token examples belong in handoffs. [test_provider_bootstrap.py](../../../../tests/test_provider_bootstrap.py) protects optional grant/text semantics; [test_provider_api.py](../../../../tests/test_provider_api.py) owns request-level auth/use/audit behavior.
