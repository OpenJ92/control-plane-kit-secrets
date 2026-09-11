Source: [test_support/tests/test_package_integrity.py](../../../../test_support/tests/test_package_integrity.py).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

These temporary-file tests feed fabricated source/gate/skip documents to inspect_package and assert accepted reports or exact finding codes. They cover collection/aliases, skip approvals, placeholders, swallowed exceptions, forbidden imports, option-name scanning and mock reporting. The fabricated test text is parsed, not executed as the application's test suite.

This is scanner-contract coverage, not evidence that real custody or provider behavior passed. [package_integrity.py](../../../../test_support/package_integrity.py) is the owner; [test.sh](../../../../test.sh) runs these support tests before the package gate.
