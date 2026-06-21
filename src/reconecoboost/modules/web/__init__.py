"""Web recon modules (v1).

Importing this package registers all web stage modules with the default
registry. Each stage lives in its own module file and is independently
replaceable.
"""

from . import parsers  # noqa: F401  (registers the v1 web parsers first)
from . import (  # noqa: F401  (imported for registration side effects)
    alive_detection,
    asset_discovery,
    content_subdomains,
    crawling,
    dir_bruteforce,
    dns_resolve,
    historical_urls,
    js_fetch,
    js_intel,
    normalization,
    nuclei_scan,
    permutation,
    screenshot,
    secret_scan,
    tech_fingerprint,
    triage,
    url_probe,
    vhost_discovery,
)
