"""secprim — shared security primitives.

One tested implementation of each boundary that the root-cause analysis
(ROOT-CAUSES.md) found re-derived, badly, across projects:

- boundary   RC-1  validate shape/type/domain/path at the edge
- bounded    RC-2  put a ceiling on size/time/expansion of untrusted input
- child_env  RC-3/5  allow-listed environments for child processes
- secrets    RC-5  secrets from one place, written with 0600
- safe_fetch RC-4  pinned, egress-validated HTTP fetch (closes DNS-rebinding)

Every failure is a subclass of `MalformedInput` (a ValueError), so a web layer
maps one type to HTTP 400 and a batch job maps it to a reported failure.
"""
from .boundary import (  # noqa: F401
    MalformedInput, as_dict, as_list, as_str, finite_float, contained_path,
)
from .bounded import (  # noqa: F401
    TooLarge, bounded_read, safe_xml_fromstring, safe_zip_members, redos_probe,
)
from .child_env import child_env, assert_no_secrets  # noqa: F401
from .secrets import (  # noqa: F401
    MissingSecret, require_secret, write_private, app_env, is_dev, is_production,
)
