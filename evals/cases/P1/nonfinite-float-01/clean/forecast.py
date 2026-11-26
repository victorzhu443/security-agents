from secprim import finite_float

DEFAULT_MARGINAL_COST = 25.0
MAX_MARGINAL_COST = 10_000.0     # $/MWh: nothing legitimate is above the offer cap


def marginal_cost(raw):
    """Boundary validation (RC-1): a real, finite number in range, or MalformedInput."""
    return finite_float(raw if raw is not None else DEFAULT_MARGINAL_COST,
                        "marginal_cost", lo=0.0, hi=MAX_MARGINAL_COST)
