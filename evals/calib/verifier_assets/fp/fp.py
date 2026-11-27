# Dimension `fp`: negatives score 1.0 iff no finding names an fp_files entry (the false-positive
# proxy; fp rate = 1 - score over negatives). 1.0 "not-applicable" on positives.
from rewardkit import criteria

criteria.no_class_finding(weight=1.0)
