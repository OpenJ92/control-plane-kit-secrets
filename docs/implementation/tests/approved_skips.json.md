Source: [tests/approved_skips.json](../../../tests/approved_skips.json).
Maintain this document alongside its source file. When the source or relevant imported contracts change, verify and update this companion in the same change.

The current empty array grants no conditional skip exceptions. The [integrity scanner](../../../test_support/package_integrity.py) matches approved identity and reason, rejects stale/duplicate entries, and still rejects unconditional or literal-condition skips. Editing the list does not authorize weaker acceptance; any exception needs an explicit reviewed reason under [AGENTS.md](../../../AGENTS.md).
