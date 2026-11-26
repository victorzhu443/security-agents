DEFAULT_MARGINAL_COST = 25.0


def marginal_cost(raw):
    """?marginal_cost= as request.args hands it over (a str, or the default when absent).

    float() accepts "nan", "inf" and "1e999"; the value then reaches the margin."""
    return float(raw if raw is not None else DEFAULT_MARGINAL_COST)
