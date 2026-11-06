Source: [tests/test_sample_factory.py](../../../tests/test_sample_factory.py).
Maintain this document alongside its source and relevant imported contracts.

The first Secrets #87 law exercises the existing required-control factory with an independently supplied Core sample binding. It requires actual SDK route installation before the existing initializer, exactly one provider initialization, and unchanged ordinary ready behavior. Disposable private test inputs stay inside the ordinary owning Docker gate; no product definition or public credential fixture is created. The intended first failure is missing optional factory behavior, not import/collection failure.
