"""Release publication guards; external HTTP calls are replaced at the boundary."""

import base64
import datetime
import importlib.util
import io
import json
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
NOTES = "Linux support.\n\n### Changes\n- Add TPM support.\n\n### Fixes\n- Fix setup."


@pytest.fixture
def release():
    path = ROOT / "tools/finalize_release.py"
    assert path.is_file(), "release finalization is not implemented"
    spec = importlib.util.spec_from_file_location("finalize_release", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GitHub:
    """In-memory remote state: assert resulting objects, not mock call counts."""

    def __init__(self):
        self.tag = None
        self.tag_object = None
        self.release = None
        self.prs = [
            {
                "number": 186,
                "merged_at": "2026-10-07T00:00:00Z",
                "merge_commit_sha": SHA,
                "base": {"ref": "main"},
                "head": {"ref": "dev"},
                "body": NOTES,
            }
        ]
        self.fail_release = False

    def __call__(self, path, payload=None):
        if path.startswith(f"commits/{SHA}/pulls?"):
            return self.prs
        if path.startswith("git/ref/tags/"):
            return self.tag
        if path == "git/tags/tag-object":
            return self.tag_object
        if path.startswith("releases/tags/"):
            return self.release if self.release and not self.release["draft"] else None
        if path.startswith("releases?per_page=100&page="):
            return [self.release] if self.release else []
        if path == "git/tags":
            self.tag_object = dict(payload, sha="tag-object")
            # GitHub returns the target as a typed object, unlike POST input.
            self.tag_object["object"] = {"type": payload["type"], "sha": payload["object"]}
            return self.tag_object
        if path == "git/refs":
            assert self.tag is None, "must never overwrite an existing tag"
            self.tag = {"ref": payload["ref"], "object": {"type": "tag", "sha": payload["sha"]}}
            return self.tag
        if path == "releases":
            if self.fail_release:
                raise RuntimeError("temporary GitHub outage")
            assert self.release is None, "must never duplicate a release"
            self.release = dict(payload, html_url="https://github.com/example/repo/releases/tag/v0.2.0a1")
            return self.release
        raise AssertionError(f"Unexpected API request: {path}")


@pytest.fixture
def remote(release, monkeypatch):
    github = GitHub()
    monkeypatch.setattr(release, "verify_pypi", lambda *args: None)
    return github


@pytest.mark.parametrize(
    ("version", "prerelease"), [("0.2.0a1", True), ("0.2.0rc1", True), ("0.2.0.dev1", True), ("0.2.0", False)]
)
def test_creates_annotated_tag_on_published_commit_with_pr_notes(release, remote, version, prerelease):
    release.finalize(remote, version, SHA)
    assert remote.tag["ref"] == f"refs/tags/v{version}"
    assert remote.tag_object["object"] == {"type": "commit", "sha": SHA}
    assert remote.tag_object["message"] == NOTES
    assert remote.release["body"] == NOTES
    assert remote.release["target_commitish"] == SHA
    assert remote.release["prerelease"] is prerelease
    assert remote.release["draft"] is False


def test_repeat_preserves_release_and_editor_changes(release, remote):
    release.finalize(remote, "0.2.0a1", SHA)
    remote.release["body"] += "\nHuman correction."
    first = dict(remote.release)
    release.finalize(remote, "0.2.0a1", SHA)
    assert remote.release == first


def test_dry_run_checks_without_creating_objects(release, remote):
    result = release.finalize(remote, "0.2.0a1", SHA, dry_run=True)
    assert "no changes made" in result
    assert remote.tag is None
    assert remote.release is None


@pytest.mark.parametrize("field", ["draft", "prerelease"])
def test_existing_release_with_wrong_status_is_not_overwritten(release, remote, field):
    release.finalize(remote, "0.2.0a1", SHA)
    remote.release[field] = not remote.release[field]
    before = dict(remote.release)
    with pytest.raises(ValueError, match="incompatible"):
        release.finalize(remote, "0.2.0a1", SHA)
    assert remote.release == before


def test_missing_tag_on_final_recheck_does_not_create_release(release, remote):
    def disappearing(path, payload=None):
        result = remote(path, payload)
        if path == "git/refs":
            remote.tag = None
        return result

    with pytest.raises(ValueError, match="disappeared"):
        release.finalize(disappearing, "0.2.0a1", SHA)
    assert remote.release is None


def test_resumes_after_tag_created_but_release_failed(release, remote):
    remote.fail_release = True
    with pytest.raises(RuntimeError, match="outage"):
        release.finalize(remote, "0.2.0a1", SHA)
    tag = dict(remote.tag)
    remote.fail_release = False
    release.finalize(remote, "0.2.0a1", SHA)
    assert remote.tag == tag
    assert remote.release["body"] == NOTES


@pytest.mark.parametrize("annotated", [False, True])
def test_refuses_tag_pointing_to_another_commit(release, remote, annotated):
    remote.tag = {"object": {"type": "tag" if annotated else "commit", "sha": "tag-object" if annotated else "b" * 40}}
    remote.tag_object = {"object": {"type": "commit", "sha": "b" * 40}}
    with pytest.raises(ValueError, match="different commit"):
        release.finalize(remote, "0.2.0a1", SHA)
    assert remote.release is None


@pytest.mark.parametrize("change", ["unmerged", "wrong_base", "wrong_head", "wrong_sha", "empty_notes", "duplicate"])
def test_requires_unique_merged_release_pr_with_notes(release, remote, change):
    pr = remote.prs[0]
    if change == "unmerged":
        pr["merged_at"] = None
    elif change == "wrong_base":
        pr["base"]["ref"] = "dev"
    elif change == "wrong_head":
        pr["head"]["ref"] = "feature"
    elif change == "wrong_sha":
        pr["merge_commit_sha"] = "b" * 40
    elif change == "empty_notes":
        pr["body"] = "### Changes\n\n### Fixes\n"
    else:
        remote.prs.append(dict(pr, number=187))
    with pytest.raises(ValueError):
        release.finalize(remote, "0.2.0a1", SHA)
    assert remote.tag is None
    assert remote.release is None


@pytest.mark.parametrize("version", ["v0.2.0", "0.0.0.dev0", "bad", "0.2.0+local"])
def test_invalid_or_reservation_version_never_writes(release, remote, version):
    with pytest.raises(ValueError):
        release.finalize(remote, version, SHA)
    assert remote.tag is None


def test_missing_pypi_publication_prevents_tag(release, remote, monkeypatch):
    def missing(*args):
        raise ValueError("missing distribution")

    monkeypatch.setattr(release, "verify_pypi", missing)
    with pytest.raises(ValueError, match="missing distribution"):
        release.finalize(remote, "0.2.0a1", SHA)
    assert remote.tag is None


@pytest.mark.parametrize("fault", [None, "wrong_version", "missing_sdist", "yanked"])
def test_checks_both_pypi_distributions(release, monkeypatch, fault):
    visited = []

    def get(url, **kwargs):
        visited.append(url)
        name = url.split("/")[-3]
        files = [{"packagetype": "bdist_wheel", "yanked": False}, {"packagetype": "sdist", "yanked": False}]
        version = "0.2.0a1"
        if name == "mordred-hermes":
            if fault == "wrong_version":
                version = "0.2.0a0"
            elif fault == "missing_sdist":
                files.pop()
            elif fault == "yanked":
                files[0]["yanked"] = True
        return {"info": {"name": name, "version": version}, "urls": files}

    monkeypatch.setattr(release, "request_json", get)
    monkeypatch.setattr(release, "verify_provenance", lambda *args: None)
    if fault:
        with pytest.raises(ValueError):
            release.verify_pypi("0.2.0a1", "example/repo", SHA)
    else:
        release.verify_pypi("0.2.0a1", "example/repo", SHA)
    assert visited == [
        "https://pypi.org/pypi/hermes-mordred/0.2.0a1/json",
        "https://pypi.org/pypi/mordred-hermes/0.2.0a1/json",
    ]


def test_only_404_means_missing_github_object(release, monkeypatch):
    def denied(*args, **kwargs):
        raise HTTPError("https://api.github.com", 403, "Forbidden", {}, None)

    monkeypatch.setattr(release, "request_json", denied)
    api = release.GitHub("example/repo", "test-token")
    with pytest.raises(HTTPError):
        api("git/ref/tags/v0.2.0a1")


def test_404_is_not_ignored_for_writes_or_release_pr_lookup(release, monkeypatch):
    def missing(*args, **kwargs):
        raise HTTPError("https://api.github.com", 404, "Not found", {}, None)

    monkeypatch.setattr(release, "request_json", missing)
    api = release.GitHub("example/repo", "test-token")
    assert api("git/ref/tags/v0.2.0a1") is None
    assert api("releases/tags/v0.2.0a1") is None
    with pytest.raises(HTTPError):
        api("git/refs", {"ref": "refs/tags/v0.2.0a1", "sha": SHA})
    with pytest.raises(HTTPError):
        api(f"commits/{SHA}/pulls")


def test_http_post_serializes_notes_and_auth_without_shell_interpolation(release, monkeypatch):
    requests = []

    def open_request(request, *, timeout):
        requests.append(request)
        assert timeout == 30
        return io.BytesIO(b'{"sha": "tag-object"}')

    monkeypatch.setattr(release, "urlopen", open_request)
    api = release.GitHub("example/repo", "test-token")
    payload = {"message": "### Changes\n- `code` $literal 日本語", "object": SHA, "type": "commit"}
    assert api("git/tags", payload) == {"sha": "tag-object"}
    request = requests[0]
    assert request.full_url == "https://api.github.com/repos/example/repo/git/tags"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer test-token"
    assert json.loads(request.data) == payload


def test_release_pr_on_later_page_is_found(release, remote):
    def paged(path, payload=None):
        if path == f"commits/{SHA}/pulls?per_page=100&page=1":
            return [{"merged_at": None} for _ in range(100)]
        return remote(path, payload)

    assert release.release_notes(paged, SHA) == NOTES


def test_cli_rejects_source_version_mismatch_before_remote_access(release, monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["finalize_release.py", "--repo", "example/repo", "--sha", SHA, "--version", "999.0.0"]
    )
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(ValueError, match="checked-out source"):
        release.main()


def test_invalid_sha_never_writes(release, remote):
    with pytest.raises(ValueError, match="full release commit SHA"):
        release.finalize(remote, "0.2.0a1", "main")
    assert remote.tag is None


def provenance(sha=SHA, repo="example/repo", digest="c" * 64):
    """PyPI response fixture; certificate parsing stays real, HTTPS is stubbed."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.13"), b"\x0c\x28" + sha.encode()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        f"https://github.com/{repo}/.github/workflows/release.yml@refs/heads/main"
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    statement = {
        "subject": [{"name": "package.whl", "digest": {"sha256": digest}}],
        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
    }
    return {
        "attestation_bundles": [
            {
                "publisher": {"kind": "GitHub", "repository": repo, "workflow": "release.yml", "environment": "pypi"},
                "attestations": [
                    {
                        "envelope": {"statement": base64.b64encode(json.dumps(statement).encode()).decode()},
                        "verification_material": {
                            "certificate": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
                        },
                    }
                ],
            }
        ]
    }


@pytest.mark.parametrize("fault", [None, "sha", "repo", "digest", "environment", "empty"])
def test_provenance_binds_published_file_to_release_commit(release, monkeypatch, fault):
    data = provenance(
        sha="b" * 40 if fault == "sha" else SHA,
        repo="other/repo" if fault == "repo" else "example/repo",
        digest="d" * 64 if fault == "digest" else "c" * 64,
    )
    if fault == "environment":
        data["attestation_bundles"][0]["publisher"]["environment"] = "testpypi"
    if fault == "empty":
        data["attestation_bundles"] = []
    monkeypatch.setattr(release, "request_json", lambda *args, **kwargs: data)
    file = {"filename": "package.whl", "digests": {"sha256": "c" * 64}}
    if fault:
        with pytest.raises(ValueError, match="provenance"):
            release.verify_provenance("hermes-mordred", "0.2.0a1", file, "example/repo", SHA)
    else:
        release.verify_provenance("hermes-mordred", "0.2.0a1", file, "example/repo", SHA)


def test_canonical_from_another_commit_blocks_all_github_writes(release, remote, monkeypatch):
    # Restore real PyPI validation; simulate canonical A and compat B with one
    # version. The finalizer must reject A before tagging the compat SHA B.
    spec = importlib.util.spec_from_file_location("fresh_finalizer", ROOT / "tools/finalize_release.py")
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)

    def get(url, **kwargs):
        if url.endswith("/provenance"):
            return provenance(sha="b" * 40)
        return {
            "info": {"name": "hermes-mordred", "version": "0.2.0a1"},
            "urls": [
                {"filename": "package.whl", "digests": {"sha256": "c" * 64}, "packagetype": "bdist_wheel"},
                {"filename": "package.tar.gz", "digests": {"sha256": "d" * 64}, "packagetype": "sdist"},
            ],
        }

    monkeypatch.setattr(fresh, "request_json", get)
    with pytest.raises(ValueError, match="provenance"):
        fresh.finalize(remote, "0.2.0a1", SHA, repository="example/repo")
    assert remote.tag is None
    assert remote.release is None


def test_workflow_finalizes_only_after_successful_production_compat_publish():
    from ruamel.yaml import YAML

    workflow = YAML(typ="safe").load((ROOT / ".github/workflows/release.yml").read_text())
    job = workflow["jobs"].get("github-release")
    assert job is not None, "publication does not yet finalize tags and release notes"
    assert job["needs"] == "publish"
    assert job["if"] == "${{ inputs.target == 'pypi' && inputs.mode == 'compat' }}"
    assert job["permissions"] == {"contents": "write", "pull-requests": "read"}
    assert workflow["permissions"] == {"contents": "read"}
