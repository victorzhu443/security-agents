# Dimension `fix`: hidden test (after tests/hidden.patch) and the project suite, all-pass.
# Reasoning carries `rc=<n>` for the validity gate (nop: hidden 0 with rc=1, suite 1; oracle: both 1).
from rewardkit import criteria

criteria.hidden_test_passes(weight=1.0)
criteria.suite_passes(weight=1.0)
