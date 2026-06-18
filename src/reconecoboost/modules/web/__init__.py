"""Web recon modules (v1).

Importing this package registers all web stage modules with the default
registry. Each stage lives in its own module file and is independently
replaceable.
"""

from . import parsers  # noqa: F401  (registers the v1 web parsers first)
from . import (  # noqa: F401  (imported for registration side effects)
    alive_detection,
    asset_discovery,
    crawling,
    dir_bruteforce,
    historical_urls,
    normalization,
    nuclei_scan,
    screenshot,
    tech_fingerprint,
    url_probe,
    vhost_discovery,
)
