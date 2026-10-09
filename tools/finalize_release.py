#!/usr/bin/env python3
"""Finalize a successful production publish with an annotated tag and release.

Called by release.yml after the compatibility upload. --dry-run performs all
remote checks without writing. Existing tags/releases are never overwritten.
"""

from __future__ import annotations

import argparse
import ast
import base64
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cryptography import x509
from packaging.version import Version

API = Callable[..., Any]


def request_json(url: str, *, token: str = "", payload: dict[str, Any] | None = None) -> Any:
    headers = {"Accept": "application/json", "User-Agent": "hermes-mordred-release"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, headers=headers, data=data)
    with urlopen(request, timeout=30) as response:
        return json.load(response)


class GitHub:
    def __init__(self, repo: str, token: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("Expected owner/repository")
        self.base = f"https://api.github.com/repos/{repo}/"
        self.token = token

    def __call__(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        try:
            return request_json(self.base + path, token=self.token, payload=payload)
        except HTTPError as exc:
            # Only absent tag/release reads may return None; auth/network/write
            # errors must stop the job, never masquerade as missing objects.
            if exc.code == 404 and payload is None and path.startswith(("git/ref/tags/", "releases/tags/")):
                return None
            raise


def matching_attestation(attestation: dict[str, Any], file: dict[str, Any], repo: str, sha: str) -> bool:
    statement = json.loads(base64.b64decode(attestation["envelope"]["statement"], validate=True))
    expected = {"name": file["filename"], "digest": {"sha256": file["digests"]["sha256"]}}
    if statement.get("subject") != [expected]:
        return False
    cert = x509.load_der_x509_certificate(
        base64.b64decode(attestation["verification_material"]["certificate"], validate=True)
    )
    # Fulcio source repository digest is DER UTF8String: tag 0x0c, length 40,
    # followed by the hexadecimal Git SHA (oid-info.md, source digest .13).
    digest = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.13")).value
    identities = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return (
        isinstance(digest, x509.UnrecognizedExtension)
        and digest.value == b"\x0c\x28" + sha.encode("ascii")
        and f"https://github.com/{repo}/.github/workflows/release.yml@refs/heads/main"
        in identities.get_values_for_type(x509.UniformResourceIdentifier)
    )


def verify_provenance(project: str, version: str, file: dict[str, Any], repo: str, sha: str) -> None:
    """Check PyPI-validated provenance served over HTTPS, not offline signatures.

    Trust boundary: the same PyPI service trusted for publication metadata.
    https://docs.pypi.org/api/integrity/
    https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
    """
    filename = quote(file["filename"], safe="")
    data = request_json(f"https://pypi.org/integrity/{project}/{version}/{filename}/provenance")
    publisher = {"kind": "GitHub", "repository": repo, "workflow": "release.yml", "environment": "pypi"}
    for bundle in data["attestation_bundles"]:
        if any(bundle["publisher"].get(key) != value for key, value in publisher.items()):
            continue
        if any(matching_attestation(item, file, repo, sha) for item in bundle["attestations"]):
            return
    raise ValueError(f"PyPI provenance for {file['filename']} does not match {repo} at {sha}")


def verify_pypi(version: str, repo: str, sha: str) -> None:
    for project in ("hermes-mordred", "mordred-hermes"):
        result = request_json(f"https://pypi.org/pypi/{project}/{version}/json")
        info = result["info"]
        files = result["urls"]
        if info["name"] != project or info["version"] != version:
            raise ValueError(f"PyPI metadata does not match {project}=={version}")
        kinds = sorted(item["packagetype"] for item in files)
        if kinds != ["bdist_wheel", "sdist"] or any(item.get("yanked", False) for item in files):
            raise ValueError(f"Expected an unyanked wheel and sdist for {project}=={version}")
        for file in files:
            verify_provenance(project, version, file, repo, sha)


def release_notes(api: API, sha: str) -> str:
    matches: list[dict[str, Any]] = []
    page = 1
    while True:
        prs = api(f"commits/{sha}/pulls?per_page=100&page={page}")
        matches.extend(
            pr
            for pr in prs
            if pr.get("merged_at")
            and pr.get("merge_commit_sha") == sha
            and pr["base"]["ref"] == "main"
            and pr["head"]["ref"] == "dev"
        )
        if len(prs) < 100:
            break
        page += 1
    if len(matches) != 1:
        raise ValueError("Expected one merged dev-to-main release PR for this exact commit")
    notes = (matches[0].get("body") or "").strip()
    sections = re.split(r"(?m)^### ", notes)
    if not any(
        section.split("\n", 1)[0].strip() in {"Changes", "Fixes"} and re.search(r"(?m)^-\s+\S", section)
        for section in sections[1:]
    ):
        raise ValueError("Release PR needs nonempty Changes/Fixes entries")
    return notes


def check_tag(api: API, tag: str, sha: str) -> bool:
    ref = api(f"git/ref/tags/{tag}")
    if ref is None:
        return False
    obj = ref["object"]
    # Accept existing lightweight tags; new tags are always annotated.
    for _ in range(10):
        if obj["type"] != "tag":
            break
        obj = api(f"git/tags/{obj['sha']}")["object"]
    if obj["type"] != "commit" or obj["sha"] != sha:
        raise ValueError(f"Existing {tag} points to a different commit; refusing to move it")
    return True


def find_release(api: API, tag: str) -> Any:
    existing = api(f"releases/tags/{tag}")
    if existing is not None:
        return existing
    # By-tag lookup only finds published releases. The contents:write token
    # can also see drafts through the list endpoint, which must be paginated.
    page = 1
    while True:
        releases = api(f"releases?per_page=100&page={page}")
        for release in releases:
            if release["tag_name"] == tag:
                return release
        if len(releases) < 100:
            return None
        page += 1


def finalize(
    api: API, version: str, sha: str, *, repository: str = "mordredagent/hermes-mordred", dry_run: bool = False
) -> str:
    parsed = Version(version)
    if str(parsed) != version or version == "0.0.0.dev0" or parsed.local:
        raise ValueError("Expected a canonical, non-reservation public version")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Expected the full release commit SHA")
    verify_pypi(version, repository, sha)
    notes = release_notes(api, sha)
    tag = f"v{version}"
    has_tag = check_tag(api, tag, sha)
    existing = find_release(api, tag)
    if existing is not None:
        if not has_tag or existing["draft"] or existing["prerelease"] != parsed.is_prerelease:
            raise ValueError("Existing release has incompatible tag, draft, or prerelease status")
        return str(existing["html_url"])
    if dry_run:
        return f"Validated {tag} at {sha}; no changes made"
    if not has_tag:
        obj = api("git/tags", {"tag": tag, "message": notes, "object": sha, "type": "commit"})
        # POST only; an existing ref is an error. Never PATCH/force-update tags.
        api("git/refs", {"ref": f"refs/tags/{tag}", "sha": obj["sha"]})
    # Recheck just before creating the release, including after a partial retry.
    if not check_tag(api, tag, sha):
        raise ValueError(f"Tag {tag} disappeared before Release creation")
    result = api(
        "releases",
        {
            "tag_name": tag,
            "target_commitish": sha,
            "name": tag,
            "body": notes,
            "draft": False,
            "prerelease": parsed.is_prerelease,
            "make_latest": "false" if parsed.is_prerelease else "legacy",
        },
    )
    return str(result["html_url"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / "src/mordred_hermes/__about__.py").read_text())
    versions = [
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
    ]
    if versions != [args.version]:
        raise ValueError("Requested version differs from checked-out source")
    api = GitHub(args.repo, os.environ["GH_TOKEN"])
    print(finalize(api, args.version, args.sha, repository=args.repo, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
