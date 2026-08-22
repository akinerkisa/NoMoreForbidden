# Two-repository release checklist

NoMoreForbidden uses a separate local `renikApp` checkout for integration
coverage. The lab is intentionally ignored by the parent repository's Git
index, so release the repositories in this order:

1. Review and commit the `renikApp` changes in its own repository.
2. Push `renikApp` and verify its CI/tests and `run_dev.py` are available on
   its default branch.
3. Run the NoMoreForbidden integration suite against a fresh lab checkout.
4. Review and commit the NoMoreForbidden changes.
5. Push NoMoreForbidden and verify its CI fetches the updated lab.

The parent CI deliberately fails its lab preflight if the remote checkout does
not contain `run_dev.py` and `tests/test_403_scenarios.py`. This prevents a
green CI result that silently skips the intended 403 regression matrix.

Do not commit or push either repository until the maintainer explicitly
authorizes the release step.
