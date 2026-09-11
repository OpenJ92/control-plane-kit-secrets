Source: [test_support/package_integrity.py](../../../test_support/package_integrity.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

This source scanner reports selected unittest collection, skip, placeholder, swallowed-exception, legacy-import and gate-option findings. It parses source/test ASTs, records test identities and mock locations, and compares conditional skips with explicit identity/reason approvals. Mocks are reported, not automatically rejected.

Its test count is static discovery evidence, not executed methods or behavioral adequacy. Name/AST/regex checks are deliberately bounded patterns, not a proof that every dynamic test or shell implementation is sound. Gate scanning flags proof-changing option names rather than executing shell control flow. Findings can contain source paths or parse-error text; this is a repository diagnostic, not a public redaction API.

The CLI returns nonzero on findings. [test.sh](../../../test.sh) invokes it inside Docker; [test_package_integrity.py](../../../test_support/tests/test_package_integrity.py) owns synthetic scanner cases. Changes to scanner policy require those cases, not new application behavior.
