# Dimension `recall`: a finding on a fix file inside a reference hunk (± 20 lines), or a claim
# whose oracle is the fix test. 1.0 "not-applicable" on negatives (W-D aggregates by metadata).
from rewardkit import criteria

criteria.finding_in_fix_hunk(weight=1.0)
