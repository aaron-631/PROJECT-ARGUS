"""
Ingress Adapter — normalizes local directories and Git repositories into ScanContext.
"""


class ScanContext:
    """Unified representation of the target being evaluated."""

    def __init__(self, source_path: str, source_type: str):
        self.source_path = source_path
        self.source_type = source_type  # "local" | "git"
        self.files: dict = {}


def ingest_local(path: str) -> ScanContext:
    # TODO: Week 1-2 — walk directory, normalize files
    raise NotImplementedError


def ingest_git(repo_url: str) -> ScanContext:
    # TODO: Week 1-2 — clone with hook prevention, normalize files
    # git clone --depth 1 --no-tags -c core.hooksPath=/dev/null
    raise NotImplementedError
