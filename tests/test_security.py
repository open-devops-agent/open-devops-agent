"""
Security controls — emergency stop, webhook auth, Slack signatures, SSH hardening.
"""
import hashlib
import hmac
import json
import os
import multiprocessing
import runpy
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.webhook_auth import (
    verify_hmac_sha256_signature,
    verify_slack_signature,
    verify_webhook_request,
)
from services.incident_queue import IncidentQueue
from services.incident_store import IncidentStore
from storage.memory_storage import MemoryStorage
from tools.executor import SafeExecutor
from tools.safety import requires_configured_approval
from tools.ssh_utils import build_ssh_command

# Header values reach the application latin-1-decoded, so an unauthenticated
# caller can put non-ASCII characters into a signature header.
NON_ASCII_WEBHOOK_SIGNATURE = "sha256=\xff\xfe"
NON_ASCII_SLACK_SIGNATURE = "v0=\xff\xfe"

# Well-formed (hex, right length) but not the expected digest.
WRONG_WEBHOOK_SIGNATURE = "sha256=" + "0" * 64
WRONG_SLACK_SIGNATURE = "v0=" + "0" * 64


class TestEmergencyStop:
    @pytest.mark.asyncio
    async def test_blocks_mutating_commands(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        result = await executor.run_safe("kubectl rollout restart deployment/api")
        assert result.get("emergency_stop") is True
        assert result.get("blocked") is True

    @pytest.mark.asyncio
    async def test_allows_read_only_commands(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        with patch("asyncio.create_subprocess_shell") as mock_proc:
            mock_proc.return_value = AsyncMock(
                returncode=0,
                communicate=AsyncMock(return_value=(b"ok", b"")),
            )
            result = await executor.run_safe("kubectl get pods")
            assert result.get("success") is True

    @pytest.mark.asyncio
    async def test_blocks_approved_run_during_emergency_stop(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        executor = SafeExecutor()
        result = await executor.run("systemctl restart nginx")
        assert result.get("emergency_stop") is True


class TestRequireApprovalFor:
    def test_rollback_requires_approval(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR", "rollback")
        assert requires_configured_approval("kubectl rollout undo deployment/api") is True

    def test_unlisted_action_not_forced(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_APPROVAL_FOR", "delete")
        assert requires_configured_approval("systemctl restart nginx") is False


class TestWebhookAuth:
    def test_valid_hmac_signature(self):
        secret = "test-secret"
        payload = b'{"type":"server"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_hmac_sha256_signature(payload, sig, secret) is True

    def test_rejects_invalid_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "secret")
        assert verify_webhook_request(b"{}", "sha256=deadbeef") is False

    def test_rejects_when_no_secret_configured(self, monkeypatch):
        monkeypatch.delenv("WEBHOOK_SECRET", raising=False)
        assert verify_webhook_request(b"{}", None) is False

    # Fail-closed invariant: any signature that is not a byte-for-byte match of the
    # expected signature must be rejected — malformed, empty, absent or simply
    # incorrect. No input turns a rejection into an acceptance, and none raises.

    def test_rejects_non_ascii_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", NON_ASCII_WEBHOOK_SIGNATURE) is False

    def test_rejects_non_ascii_signature_in_hmac_helper(self):
        payload = b'{"type":"server"}'
        assert (
            verify_hmac_sha256_signature(payload, NON_ASCII_WEBHOOK_SIGNATURE, "test-secret")
            is False
        )

    def test_rejects_empty_signature(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", "") is False

    def test_rejects_absent_signature_when_secret_configured(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b"{}", None) is False

    def test_accepts_correct_signature(self, monkeypatch):
        """Regression guard: fail-closed handling must not break the accept path."""
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        payload = b'{"type":"server"}'
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_webhook_request(payload, sig) is True

    def test_rejects_incorrect_but_well_formed_signature(self, monkeypatch):
        """Regression guard: fail-closed handling must not make the compare permissive."""
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        assert verify_webhook_request(b'{"type":"server"}', WRONG_WEBHOOK_SIGNATURE) is False

    def test_accepts_gitlab_static_token(self, monkeypatch):
        from api.webhook_auth import verify_webhook_auth

        monkeypatch.setenv("WEBHOOK_SECRET", "gitlab-secret")
        assert verify_webhook_auth(b'{"object_kind":"merge_request"}', static_token="gitlab-secret") is True
        assert verify_webhook_auth(b'{"object_kind":"merge_request"}', static_token="wrong") is False
        assert verify_webhook_auth(b"{}", signature=None, static_token=None) is False


class TestSlackSignature:
    def test_valid_slack_signature(self):
        secret = "slack-secret"
        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()))
        basestring = f"v0:{timestamp}:{body.decode()}"
        signature = "v0=" + hmac.new(
            secret.encode(), basestring.encode(), hashlib.sha256
        ).hexdigest()
        assert verify_slack_signature(body, timestamp, signature, secret) is True

    def test_rejects_stale_timestamp(self):
        secret = "slack-secret"
        body = b"payload=%7B%7D"
        timestamp = str(int(time.time()) - 600)
        basestring = f"v0:{timestamp}:{body.decode()}"
        signature = "v0=" + hmac.new(
            secret.encode(), basestring.encode(), hashlib.sha256
        ).hexdigest()
        assert verify_slack_signature(body, timestamp, signature, secret) is False

    # Same fail-closed invariant as TestWebhookAuth. The accept path is guarded by
    # test_valid_slack_signature above, which must keep passing.

    def test_rejects_non_ascii_signature(self):
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(
                b"payload=%7B%7D", timestamp, NON_ASCII_SLACK_SIGNATURE, "slack-secret"
            )
            is False
        )

    def test_rejects_empty_signature(self):
        timestamp = str(int(time.time()))
        assert verify_slack_signature(b"payload=%7B%7D", timestamp, "", "slack-secret") is False

    def test_rejects_absent_signature(self):
        timestamp = str(int(time.time()))
        assert verify_slack_signature(b"payload=%7B%7D", timestamp, None, "slack-secret") is False

    def test_rejects_incorrect_but_well_formed_signature(self):
        """Regression guard: fail-closed handling must not make the compare permissive."""
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(
                b"payload=%7B%7D", timestamp, WRONG_SLACK_SIGNATURE, "slack-secret"
            )
            is False
        )

    def test_rejects_non_utf8_body(self):
        """A body that is not UTF-8 must be rejected, not decoded lossily and not raise."""
        timestamp = str(int(time.time()))
        assert (
            verify_slack_signature(b"\xff\xfe", timestamp, WRONG_SLACK_SIGNATURE, "slack-secret")
            is False
        )


class TestSshUtils:
    def test_strict_host_key_checking_by_default(self, monkeypatch):
        monkeypatch.delenv("SSH_STRICT_HOST_KEY_CHECKING", raising=False)
        cmd = build_ssh_command("10.0.0.5", "df -h")
        assert "StrictHostKeyChecking=yes" in cmd
        assert "StrictHostKeyChecking=no" not in cmd

    def test_applies_remote_user(self, monkeypatch):
        monkeypatch.setenv("SSH_REMOTE_USER", "ubuntu")
        cmd = build_ssh_command("10.0.0.5", "uptime")
        assert "ubuntu@10.0.0.5" in cmd

    def test_allows_opt_out_for_dev(self, monkeypatch):
        monkeypatch.setenv("SSH_STRICT_HOST_KEY_CHECKING", "false")
        cmd = build_ssh_command("10.0.0.5", "uptime")
        assert "StrictHostKeyChecking=no" in cmd


class TestWebhookEndpoints:
    def test_manual_webhook_requires_signature_when_secret_set(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_SECRET", "test-secret")
        from api.server import app

        client = TestClient(app)
        response = client.post(
            "/webhook/manual",
            json={"type": "server", "description": "test"},
        )
        assert response.status_code == 401

    def test_manual_webhook_accepts_valid_signature(self, monkeypatch):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        payload = {"type": "server", "description": "test"}
        body = json.dumps(payload).encode()
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        with patch("api.server.enqueue_incident", new=AsyncMock(return_value="INC-1")):
            response = client.post(
                "/webhook/manual",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": sig,
                },
            )
        assert response.status_code == 200
        assert response.json()["status"] == "queued"

    def test_health_reports_emergency_stop(self, monkeypatch):
        monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
        from api.server import app

        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["emergency_stop"] is True

    @pytest.mark.parametrize(
        "path",
        [
            "/webhook/github",
            "/webhook/alertmanager",
            "/webhook/gitlab",
            "/webhook/bitbucket",
            "/webhook/manual",
        ],
    )
    def test_webhook_malformed_json_returns_400(self, monkeypatch, path):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        body = b"not json"
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        response = client.post(
            path,
            content=body,
            headers={"X-Hub-Signature-256": sig},
        )
        assert response.status_code == 400

    @pytest.mark.parametrize(
        "path",
        [
            "/webhook/github",
            "/webhook/alertmanager",
            "/webhook/gitlab",
            "/webhook/bitbucket",
            "/webhook/manual",
        ],
    )
    def test_webhook_non_object_json_returns_400(self, monkeypatch, path):
        secret = "test-secret"
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        from api.server import app

        body = b"null"
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

        client = TestClient(app)
        response = client.post(
            path,
            content=body,
            headers={"X-Hub-Signature-256": sig},
        )
        assert response.status_code == 400


class TestBitbucketWebhookSignature:
    @pytest.fixture
    def signed_request(self, monkeypatch):
        from api.server import app

        secret = os.urandom(32).hex()
        monkeypatch.setenv("WEBHOOK_SECRET", secret)
        body_bytes = b'{ "repository": {"slug": "example"} }\n'
        signature = "sha256=" + hmac.new(
            secret.encode(), body_bytes, hashlib.sha256
        ).hexdigest()
        return TestClient(app), body_bytes, signature

    @pytest.mark.parametrize(
        "header",
        ["X-Hub-Signature", "X-Hub-Signature-256", "X-Webhook-Signature"],
    )
    def test_accepts_valid_signature(self, signed_request, header):
        """The 200 assertion catches removal of each header's acceptance path."""
        client, body_bytes, signature = signed_request
        response = client.post(
            "/webhook/bitbucket",
            content=body_bytes,
            headers={header: signature},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"

    def test_rejects_missing_signature(self, signed_request):
        """The 401 assertion catches acceptance when all signature headers are absent."""
        client, body_bytes, _ = signed_request
        response = client.post("/webhook/bitbucket", content=body_bytes)
        assert response.status_code == 401

    @pytest.mark.parametrize(
        "header",
        ["X-Hub-Signature", "X-Hub-Signature-256", "X-Webhook-Signature"],
    )
    @pytest.mark.parametrize(
        "case", ["empty", "wrong_digest", "missing_prefix", "unknown_algorithm", "non_hex"]
    )
    def test_rejects_invalid_signature(self, signed_request, header, case):
        """The 401 assertion catches acceptance of each distinct invalid signature.

        Cases pin present-but-empty separately from absent, a wrong hex digest,
        a missing sha256= prefix, an unknown algorithm, and non-hex digest text.
        """
        client, body_bytes, signature = signed_request
        digest = signature.removeprefix("sha256=")
        wrong_digest = ("1" if digest[0] == "0" else "0") + digest[1:]
        invalid = {
            "empty": "",
            "wrong_digest": "sha256=" + wrong_digest,
            "missing_prefix": digest,
            "unknown_algorithm": "sha1=" + digest,
            "non_hex": "sha256=" + "z" * 64,
        }[case]
        response = client.post(
            "/webhook/bitbucket", content=body_bytes, headers={header: invalid}
        )
        assert response.status_code == 401

    @pytest.mark.parametrize(
        "preferred, fallback",
        [
            ("X-Hub-Signature-256", "X-Webhook-Signature"),
            ("X-Hub-Signature-256", "X-Hub-Signature"),
            ("X-Webhook-Signature", "X-Hub-Signature"),
        ],
    )
    def test_preserves_header_precedence(self, signed_request, preferred, fallback):
        """The 200 then 401 assertions catch reversed precedence or retry on failure."""
        client, body_bytes, signature = signed_request
        for preferred_value, fallback_value, expected_status in [
            (signature, WRONG_WEBHOOK_SIGNATURE, 200),
            (WRONG_WEBHOOK_SIGNATURE, signature, 401),
        ]:
            response = client.post(
                "/webhook/bitbucket",
                content=body_bytes,
                headers={preferred: preferred_value, fallback: fallback_value},
            )
            assert response.status_code == expected_status

    @pytest.mark.parametrize(
        "empty_header, fallback",
        [
            ("X-Hub-Signature-256", "X-Webhook-Signature"),
            ("X-Hub-Signature-256", "X-Hub-Signature"),
            ("X-Webhook-Signature", "X-Hub-Signature"),
        ],
    )
    def test_empty_header_allows_fallback(self, signed_request, empty_header, fallback):
        """The 200 assertion catches treating an empty header as a chosen signature."""
        client, body_bytes, signature = signed_request
        response = client.post(
            "/webhook/bitbucket",
            content=body_bytes,
            headers={empty_header: "", fallback: signature},
        )
        assert response.status_code == 200


@pytest.fixture
def bitbucket_request(monkeypatch):
    from api.server import app

    signing_key = os.urandom(32)
    monkeypatch.setenv("WEBHOOK_SECRET", signing_key.hex())

    def post(
        payload,
        event="pullrequest:created",
        org_id="tenant-ember",
        raise_server_exceptions=True,
    ):
        body = json.dumps(payload).encode()
        signature = "sha256=" + hmac.new(
            signing_key.hex().encode(), body, hashlib.sha256
        ).hexdigest()
        headers = {"X-Hub-Signature-256": signature, "X-Org-ID": org_id}
        if event is not None:
            headers["X-Event-Key"] = event
        return TestClient(app, raise_server_exceptions=raise_server_exceptions).post(
            "/webhook/bitbucket", content=body, headers=headers
        )

    return post



@pytest.fixture
def bitbucket_payload():
    return {
        "repository": {
            "workspace": {"slug": "workspace-cedar"},
            "slug": "repository-maple",
        },
        "pullrequest": {
            "id": 731,
            "state": "OPEN",
            "title": "Review this change",
            "source": {
                "branch": {"name": "feature"},
                "commit": {"hash": "commit-juniper"},
            },
            "destination": {"branch": {"name": "main"}},
        },
    }



@pytest.fixture
def review_queue(monkeypatch):
    queue = IncidentQueue(MemoryStorage())
    monkeypatch.setattr("api.server.incident_queue", queue)
    return queue




@pytest.fixture
def review_context():
    return {
        "type": "code_review",
        "scm_platform": "bitbucket",
        "repo": "workspace-cedar/repository-maple",
        "change_id": "731",
        "head_sha": "commit-juniper",
    }



@pytest.fixture
def gitlab_request(monkeypatch):
    from api.server import app

    signing_key = os.urandom(32).hex()
    monkeypatch.setenv("WEBHOOK_SECRET", signing_key)

    def post(payload, event="Merge Request Hook", org_id="tenant-ash", static_token=False):
        body = json.dumps(payload).encode()
        headers = {"X-Org-ID": org_id}
        if event is not None:
            headers["X-Gitlab-Event"] = event
        if static_token:
            headers["X-Gitlab-Token"] = signing_key
        else:
            headers["X-Hub-Signature-256"] = "sha256=" + hmac.new(
                signing_key.encode(), body, hashlib.sha256
            ).hexdigest()
        return TestClient(app).post("/webhook/gitlab", content=body, headers=headers)

    return post



@pytest.fixture
def gitlab_payload():
    return {
        "object_kind": "merge_request",
        "project": {"id": 482, "path_with_namespace": "group-oak/repository-pine"},
        "user": {"username": "reviewer"},
        "object_attributes": {
            "iid": 953,
            "action": "open",
            "state": "opened",
            "title": "Review the merge request",
            "source_branch": "feature",
            "target_branch": "main",
            "last_commit": {"id": "commit-willow"},
        },
    }



def _review_marker_key(storage, org_id, incident_id):
    """Read the admitted attempt's reference instead of deriving it from its ID."""
    for key in (storage.queue_key(org_id, "pending", incident_id),
                storage.review_claim_key(org_id, incident_id),
                storage.queue_key(org_id, "failed", incident_id)):
        entry = storage.get_json(key)
        if entry and entry.get("review_key"):
            return entry["review_key"]
    for key in storage.list_keys(storage.org_prefix(org_id, "review_dedupe")):
        entry = storage.get_json(key)
        if entry and entry["incident_id"] == incident_id:
            return key
    raise AssertionError("Review attempt has no marker reference")


class TestGitlabReviewTriggers:
    @pytest.mark.parametrize("action", ["update", "approval", "approved", "unapproval", "unapproved", "close", "merge", ""])
    def test_ignores_actions_without_new_review_work(
        self, gitlab_request, gitlab_payload, action
    ):
        gitlab_payload["object_attributes"]["action"] = action
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            response = gitlab_request(gitlab_payload)
            assert response.status_code == 200
            assert response.json()["status"] == "ignored"
            assert enqueue.call_count == 0

            gitlab_payload["object_attributes"]["action"] = "open"
            positive = gitlab_request(gitlab_payload)
            assert positive.status_code == 200
            assert positive.json()["status"] == "queued"
            assert enqueue.call_count == 1


    @pytest.mark.parametrize("action", ["open", "reopen", "update"])
    @pytest.mark.parametrize("event", ["Merge Request Hook", None])
    def test_ready_actions_record_head_and_preserve_draft_guards(
        self, gitlab_request, gitlab_payload, action, event
    ):
        attrs = gitlab_payload["object_attributes"]
        attrs["action"] = action
        if action == "update":
            attrs["oldrev"] = "commit-previous"
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            for field in ("draft", "work_in_progress"):
                draft = deepcopy(gitlab_payload)
                draft["object_attributes"][field] = True
                response = gitlab_request(draft, event)
                assert response.status_code == 200
                assert response.json()["status"] == "ignored"
                assert enqueue.call_count == 0

            response = gitlab_request(gitlab_payload, event)
            assert response.status_code == 200
            assert response.json() == {
                "status": "queued",
                "type": "code_review",
                "incident_id": "INC-review",
            }
            assert enqueue.call_count == 1
            context = enqueue.call_args.args[0]
            assert context.get("head_sha") == "commit-willow"
            assert context["type"] == "code_review"
            assert context["scm_platform"] == "gitlab"
            assert context["repo"] == "482"
            assert context["change_id"] == "953"


    @pytest.mark.parametrize("state", ["pending", "processing", "completed", "failed"])
    def test_duplicate_head_returns_original_response_across_states(
        self, gitlab_request, gitlab_payload, review_queue, state
    ):
        first = gitlab_request(gitlab_payload)
        assert first.status_code == 200
        incident_id = first.json()["incident_id"]
        if state != "pending":
            assert review_queue.claim_next("tenant-ash")["incident_id"] == incident_id
        if state == "completed":
            review_queue.mark_completed("tenant-ash", incident_id, {})
        elif state == "failed":
            review_queue.mark_failed("tenant-ash", incident_id, "review unavailable")
        gitlab_payload["object_attributes"].update(
            action="update", oldrev="commit-before", title="Edited title"
        )
        repeat = gitlab_request(gitlab_payload)
        assert repeat.status_code == 200
        expected_id = repeat.json()["incident_id"] if state == "failed" else incident_id
        assert (expected_id != incident_id) == (state == "failed")
        assert repeat.json() == {
            "status": "queued",
            "type": "code_review",
            "incident_id": expected_id,
        }
        assert gitlab_request(gitlab_payload).json() == repeat.json()
        keys = review_queue.storage.list_keys("tenant-ash/review_dedupe/")
        assert len(keys) == 1
        entry = review_queue.storage.get_json(keys[0])
        assert entry["status"] == ("pending" if state == "failed" else state)
        if state == "failed":
            failed_key = review_queue.storage.queue_key(entry["org_id"], "failed", incident_id)
            failed = review_queue.storage.get_json(failed_key)
            assert failed and failed["status"] == "failed"
            assert failed["context"]["head_sha"] == entry["context"]["head_sha"]
            assert entry["incident_id"] != incident_id
        org = entry["org_id"]
        active_keys = review_queue.storage.list_keys(f"{org}/queue/pending/")
        assert len(active_keys) == (0 if state == "completed" else 1)
        assert entry["context"].get("head_sha") == "commit-willow"


    @pytest.mark.parametrize("field", ["org_id", "head_sha", "repo", "change_id"])
    def test_distinct_identity_creates_new_review(
        self, gitlab_request, gitlab_payload, review_queue, field
    ):
        first = gitlab_request(gitlab_payload)
        repeat = gitlab_request(gitlab_payload)
        assert first.status_code == repeat.status_code == 200
        assert repeat.json() == first.json()
        gitlab_payload["object_attributes"].update(action="update", oldrev="commit-before")
        org_id = "tenant-ash"
        if field == "org_id":
            org_id = "tenant-elm"
        elif field == "head_sha":
            gitlab_payload["object_attributes"]["last_commit"]["id"] = "commit-poplar"
        elif field == "repo":
            gitlab_payload["project"]["id"] = 674
        else:
            gitlab_payload["object_attributes"]["iid"] = 816
        second = gitlab_request(gitlab_payload, org_id=org_id)
        second_repeat = gitlab_request(gitlab_payload, org_id=org_id)
        assert second.status_code == second_repeat.status_code == 200
        assert second.json() == second_repeat.json()
        assert second.json()["incident_id"] != first.json()["incident_id"]
        keys = [key for key in review_queue.storage.list_keys("") if "/review_dedupe/" in key]
        assert len(keys) == 2
        assert {review_queue.storage.get_json(key)["org_id"] for key in keys} == {
            "tenant-ash",
            org_id,
        }


    @pytest.mark.parametrize("delimiter", [":", '\",\"'])
    def test_identity_field_boundaries_do_not_collide(
        self, gitlab_request, gitlab_payload, review_queue, delimiter
    ):
        del gitlab_payload["project"]["id"]
        gitlab_payload["project"]["path_with_namespace"] = f"group-oak{delimiter}842"
        first = gitlab_request(gitlab_payload)
        repeat = gitlab_request(gitlab_payload)
        assert first.status_code == repeat.status_code == 200
        assert repeat.json() == first.json()
        # Moving a delimiter across adjacent fields must form a different identity.
        gitlab_payload["project"]["path_with_namespace"] = "group-oak"
        gitlab_payload["object_attributes"]["iid"] = f"842{delimiter}953"
        second = gitlab_request(gitlab_payload)
        second_repeat = gitlab_request(gitlab_payload)
        assert second.status_code == second_repeat.status_code == 200
        assert second_repeat.json() == second.json()
        assert second.json()["incident_id"] != first.json()["incident_id"]
        assert len(review_queue.storage.list_keys("tenant-ash/review_dedupe/")) == 2


    @pytest.mark.parametrize("committed", [False, True])
    def test_write_error_succeeds_only_when_record_persisted(
        self, monkeypatch, gitlab_request, gitlab_payload, review_queue, committed
    ):
        storage = review_queue.storage
        put = storage.put_json_if_absent

        def lose_acknowledgement(key, data):
            if "/review_dedupe/" not in key:
                return put(key, data)
            if committed:
                put(key, data)
            raise RuntimeError("Review write unavailable")

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", lose_acknowledgement)
            if committed:
                response = gitlab_request(gitlab_payload)
                assert response.status_code == 200
                keys = storage.list_keys("tenant-ash/review_dedupe/")
                assert len(keys) == 1
                entry = storage.get_json(keys[0])
                assert entry["context"].get("head_sha") == "commit-willow"
                assert response.json() == {
                    "status": "queued",
                    "type": "code_review",
                    "incident_id": entry["incident_id"],
                }
            else:
                failure = None
                try:
                    gitlab_request(gitlab_payload)
                except RuntimeError as error:
                    failure = error
                assert failure is not None
                assert str(failure) == "Review write unavailable"
                assert storage.list_keys("tenant-ash/review_dedupe/") == []

        retry = gitlab_request(gitlab_payload)
        assert retry.status_code == 200
        keys = storage.list_keys("tenant-ash/review_dedupe/")
        assert len(keys) == 1
        assert retry.json()["incident_id"] == storage.get_json(keys[0])["incident_id"]
        if committed:
            assert retry.json() == response.json()


    def test_static_token_review_and_failed_pipeline(
        self, gitlab_request, gitlab_payload, review_queue
    ):
        review = gitlab_request(gitlab_payload, static_token=True)
        assert review.status_code == 200
        keys = review_queue.storage.list_keys("tenant-ash/review_dedupe/")
        assert len(keys) == 1
        entry = review_queue.storage.get_json(keys[0])
        assert entry["context"].get("head_sha") == "commit-willow"
        pipeline = {
            "object_kind": "pipeline",
            "project": {"id": 482},
            "object_attributes": {"id": 617, "status": "failed"},
        }
        response = gitlab_request(pipeline, event=None)
        assert response.status_code == 200
        assert response.json()["status"] == "queued"
        assert response.json()["type"] == "cicd"
        keys = [key for key in review_queue.storage.list_keys("tenant-ash/queue/pending/")
                if review_queue.storage.get_json(key)["context"]["type"] == "cicd"]
        assert len(keys) == 1
        assert review_queue.storage.get_json(keys[0])["context"] == {
            "type": "cicd",
            "source": "gitlab_ci",
            "org_id": "tenant-ash",
            "project_id": "482",
            "pipeline_id": 617,
            "labels": {"cicd_platform": "gitlab"},
        }



class TestBitbucketReviewTriggers:
    @pytest.mark.parametrize(
        "event",
        [
            "pullrequest:comment_created",
            "pullrequest:fulfilled",
            "pullrequest:rejected",
            None,
        ],
    )
    def test_ignores_non_review_events(self, bitbucket_request, bitbucket_payload, event):
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            response = bitbucket_request(bitbucket_payload, event)
            assert response.status_code == 200
            assert response.json()["status"] == "ignored"
            assert enqueue.call_count == 0

            response = bitbucket_request(bitbucket_payload)
            assert response.status_code == 200
            assert response.json()["status"] == "queued"
            assert enqueue.call_count == 1


    @pytest.mark.parametrize("event", ["pullrequest:created", "pullrequest:updated"])
    def test_reviews_only_ready_prs_and_records_head(
        self, bitbucket_request, bitbucket_payload, event
    ):
        with patch(
            "api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")
        ) as enqueue:
            for draft in ({"draft": True}, {"state": "DRAFT"}, {"state": "MERGED"}, {"state": "DECLINED"}, {"state": ""}):
                payload = dict(bitbucket_payload)
                payload["pullrequest"] = {**bitbucket_payload["pullrequest"], **draft}
                response = bitbucket_request(payload, event)
                assert response.status_code == 200
                assert response.json()["status"] == "ignored"
                assert enqueue.call_count == 0

            response = bitbucket_request(bitbucket_payload, event)
            assert response.status_code == 200
            assert response.json()["status"] == "queued"
            assert response.json()["type"] == "code_review"
            assert enqueue.call_count == 1
            context = enqueue.call_args.args[0]
            assert context.get("head_sha") == "commit-juniper"
            assert context["type"] == "code_review"


    @pytest.mark.parametrize("state", ["pending", "processing", "completed", "failed"])
    def test_duplicate_head_across_queue_states(
        self, bitbucket_request, bitbucket_payload, review_queue, state
    ):
        first = bitbucket_request(bitbucket_payload)
        assert first.status_code == 200
        assert first.json()["status"] == "queued"
        incident_id = first.json()["incident_id"]
        if state != "pending":
            entry = review_queue.claim_next("tenant-ember")
            assert entry["incident_id"] == incident_id
        if state == "completed":
            review_queue.mark_completed("tenant-ember", incident_id, {})
        elif state == "failed":
            review_queue.mark_failed("tenant-ember", incident_id, "review unavailable")

        bitbucket_payload["pullrequest"]["title"] = "Edited review title"
        repeat = bitbucket_request(bitbucket_payload, "pullrequest:updated")
        assert repeat.status_code == 200
        keys = review_queue.storage.list_keys("tenant-ember/review_dedupe/")
        assert len(keys) == 1
        entry = review_queue.storage.get_json(keys[0])
        assert entry["status"] == ("pending" if state == "failed" else state)
        if state == "failed":
            failed_key = review_queue.storage.queue_key(entry["org_id"], "failed", incident_id)
            failed = review_queue.storage.get_json(failed_key)
            assert failed and failed["status"] == "failed"
            assert failed["context"]["head_sha"] == entry["context"]["head_sha"]
            assert entry["incident_id"] != incident_id
        org = entry["org_id"]
        active_keys = review_queue.storage.list_keys(f"{org}/queue/pending/")
        assert len(active_keys) == (0 if state == "completed" else 1)
        assert entry["context"].get("head_sha") == "commit-juniper"


    @pytest.mark.parametrize("field", ["org_id", "repo", "change_id", "head_sha"])
    def test_distinct_review_identity_enqueues_separately(
        self, bitbucket_request, bitbucket_payload, review_queue, field
    ):
        first = bitbucket_request(bitbucket_payload)
        bitbucket_request(bitbucket_payload)
        assert len(review_queue.storage.list_keys("tenant-ember/review_dedupe/")) == 1

        org_id = "tenant-ember"
        if field == "org_id":
            org_id = "tenant-birch"
        elif field == "repo":
            bitbucket_payload["repository"]["slug"] = "repository-willow"
        elif field == "change_id":
            bitbucket_payload["pullrequest"]["id"] = 845
        else:
            bitbucket_payload["pullrequest"]["source"]["commit"]["hash"] = "commit-spruce"
        second = bitbucket_request(bitbucket_payload, "pullrequest:updated", org_id)
        assert first.status_code == second.status_code == 200
        assert second.json()["status"] == "queued"
        assert first.json()["incident_id"] != second.json()["incident_id"]
        bitbucket_request(bitbucket_payload, "pullrequest:updated", org_id)
        keys = [key for key in review_queue.storage.list_keys("") if "/review_dedupe/" in key]
        assert len(keys) == 2
        assert {review_queue.storage.get_json(key)["org_id"] for key in keys} == {
            "tenant-ember",
            org_id,
        }


    def test_concurrent_duplicate_deliveries_enqueue_once(
        self, bitbucket_request, bitbucket_payload, review_queue
    ):
        with ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(
                executor.map(lambda _: bitbucket_request(bitbucket_payload), range(8))
            )
        assert all(response.status_code == 200 for response in responses)
        assert len(review_queue.storage.list_keys("tenant-ember/review_dedupe/")) == 1


    def test_shared_dedupe_includes_provider(self, review_queue):
        context = {
            "type": "code_review",
            "scm_platform": "bitbucket",
            "repo": "workspace-cedar/repository-maple",
            "change_id": "731",
            "head_sha": "commit-juniper",
        }
        first = review_queue.enqueue("tenant-ember", context)
        review_queue.enqueue("tenant-ember", context)
        assert len(review_queue.storage.list_keys("tenant-ember/review_dedupe/")) == 1
        second = review_queue.enqueue("tenant-ember", {**context, "scm_platform": "gitlab"})
        assert first != second
        assert len(review_queue.storage.list_keys("tenant-ember/review_dedupe/")) == 2



class RecordingStorage(MemoryStorage):
    """Use real storage semantics; record every listing and object read."""

    def __init__(self):
        super().__init__()
        self.reads = []
        self.listings = []

    def get_json(self, key):
        self.reads.append(key)
        return super().get_json(key)

    def list_keys(self, prefix):
        self.listings.append(prefix)
        return super().list_keys(prefix)


class TestReviewQueueDurability:
    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    def test_idle_poll_reads_do_not_grow_with_history(self, review_context, terminal, capsys, monkeypatch, bitbucket_request, bitbucket_payload):
        storage = RecordingStorage()
        queue = IncidentQueue(storage)
        counts = []
        previous_size = 0
        monkeypatch.setenv("ORG_ID", "tenant-configured")
        monkeypatch.delenv("ORG_IDS", raising=False)
        monkeypatch.setattr("api.server.incident_queue", queue)
        for size in (100, 1000):
            payload = deepcopy(bitbucket_payload)
            payload["pullrequest"]["source"]["commit"]["hash"] = str(previous_size)
            response = bitbucket_request(payload, org_id="tenant-history")
            assert response.status_code == 200
            assert "tenant-history" in queue.list_pending_org_ids()
            active = queue.claim_next("tenant-history")
            assert active and active["incident_id"] == response.json()["incident_id"]
            if terminal == "completed":
                queue.mark_completed("tenant-history", active["incident_id"], {})
            else:
                queue.mark_failed("tenant-history", active["incident_id"], "unavailable")
            assert "tenant-history" not in queue.list_pending_org_ids()
            for index in range(previous_size + 1, size):
                incident_id = queue.enqueue("tenant-history", {**review_context, "head_sha": str(index)})
                queue.claim_next("tenant-history")
                if terminal == "completed":
                    queue.mark_completed("tenant-history", incident_id, {})
                else:
                    queue.mark_failed("tenant-history", incident_id, "unavailable")
            previous_size = size
            for index in range(size):
                storage.put_json(storage.queue_key("tenant-history", "reviews", f"legacy-{index}"),
                                 {"status": terminal, "incident_id": f"legacy-{index}"})
            storage.reads.clear()
            storage.listings.clear()
            queue.list_pending_org_ids()
            assert queue.recover_stale_processing("tenant-history") == 0
            assert queue.claim_next("tenant-history") is None
            counts.append((len(storage.reads), len(storage.listings)))
            assert storage.list_keys("tenant-history/queue/pending/") == []
            assert storage.list_keys("tenant-history/queue/processing/") == []
        assert counts == [(0, 4), (0, 4)]
        capsys.readouterr()
        print(f"history=100,1000 terminal={terminal} poll (get_json,list_keys)={counts}")

    @pytest.mark.parametrize("stage", ["pending", "marker"])
    @pytest.mark.parametrize("committed", [False, True])
    @pytest.mark.parametrize("advanced", ["pending", "processing", "completed", "failed"])
    def test_lost_write_ack_across_lifecycle(self, monkeypatch, review_context, stage, committed, advanced):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        original = storage.put_json_if_absent
        fired = False

        def write(key, data):
            nonlocal fired
            matches = "/queue/pending/" in key if stage == "pending" else "/review_dedupe/" in key
            if not matches or fired:
                return original(key, data)
            fired = True
            if committed:
                original(key, data)
                if advanced != "pending":
                    if stage == "marker":
                        # Another delivery can publish while the marker reply is lost.
                        queue.enqueue("tenant", review_context)
                    claimed = queue.claim_next("tenant")
                    assert claimed is not None
                    if advanced == "completed":
                        queue.mark_completed("tenant", claimed["incident_id"], {})
                    elif advanced == "failed":
                        queue.mark_failed("tenant", claimed["incident_id"], "unavailable")
            raise RuntimeError("lost write acknowledgement")

        failure = None
        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", write)
            try:
                queue.enqueue("tenant", review_context)
            except RuntimeError as error:
                failure = error
        assert fired
        if committed and (stage == "marker" or advanced != "pending"):
            assert failure is None
        if not committed:
            assert failure is not None
            assert str(failure) == "lost write acknowledgement"
        incident_id = queue.enqueue("tenant", review_context)
        assert queue.enqueue("tenant", review_context) == incident_id
        if committed and advanced not in ("pending", "failed"):
            assert queue.claim_next("tenant") is None
        else:
            claimed = queue.claim_next("tenant")
            assert claimed is not None
            assert claimed["incident_id"] == incident_id
            assert queue.claim_next("tenant") is None

    @pytest.mark.parametrize("stage", ["slot", "pending", "marker", "claim", "processing", "terminal", "fence", "decision", "delete", "retention_index", "retention_fence", "retention_record", "failed_record", "marker_release"])
    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    def test_process_crash_recovers_once(self, review_context, stage, terminal):
        if terminal == "completed" and stage in ("failed_record", "marker_release"):
            pytest.skip("failure transition stage")
        # A real exit bypasses all enqueue/claim/terminal exception handlers.
        if "fork" not in multiprocessing.get_all_start_methods():
            pytest.skip("fork required to share the recording memory backend")
        ctx = multiprocessing.get_context("fork")
        with ctx.Manager() as manager:
            storage = MemoryStorage()
            storage._objects = manager.dict()
            storage._lock = ctx.Lock()
            # DictProxy iteration returns an iterator proxy unavailable after fork.
            storage.list_keys = lambda prefix: sorted(key for key in storage._objects.keys() if key.startswith(prefix))

            def child():
                in_retention = False
                queue = IncidentQueue(storage)
                conditional, put, delete = storage.put_json_if_absent, storage.put_json, storage.delete

                def conditional_crash(key, data):
                    result = conditional(key, data)
                    matches = {
                        "slot": "/review_heads/" in key,
                        "decision": "/review_releases/" in key,
                        "pending": "/queue/pending/" in key,
                        "marker": "/review_dedupe/" in key,
                        "claim": "/review_claims/" in key,
                    }
                    if matches.get(stage):
                        os._exit(19)
                    return result

                def put_crash(key, data):
                    result = put(key, data)
                    if ((stage == "failed_record" and "/queue/failed/" in key)
                            or (stage == "retention_fence" and "/review_claims/" in key and data.get("status") == terminal and "context" not in data)
                            or (stage == "retention_record" and terminal == "completed" and "/review_dedupe/" in key and "context" not in data)
                            or (stage == "processing" and data.get("status") == "processing")
                            or (stage == "terminal" and "/review_dedupe/" in key and data.get("status") == terminal)
                            or (stage == "fence" and "/review_claims/" in key and data.get("status") == terminal)):
                        os._exit(19)
                    return result

                def delete_crash(key):
                    if terminal == "failed" and stage.startswith("retention_") and not in_retention and "/queue/pending/" in key:
                        raise RuntimeError("index cleanup before retention")
                    result = delete(key)
                    if ((stage == "delete" and "/queue/pending/" in key)
                            or (in_retention and stage == "retention_index" and "/queue/pending/" in key)
                            or (stage == "marker_release" and "/review_dedupe/" in key)
                            or (in_retention and stage == "retention_record" and "/queue/failed/" in key)):
                        os._exit(19)
                    return result

                storage.put_json_if_absent = conditional_crash
                storage.put_json = put_crash
                storage.delete = delete_crash
                incident_id = queue.enqueue("tenant", review_context)
                assert queue.claim_next("tenant") is not None
                if stage.startswith("retention_"):
                    if terminal == "failed":
                        failure = None
                        try:
                            queue.mark_failed("tenant", incident_id, "unavailable")
                        except RuntimeError as error:
                            failure = error
                        assert str(failure) == "index cleanup before retention"
                        record_key = storage.queue_key("tenant", "failed", incident_id)
                    else:
                        record_key = _review_marker_key(storage, "tenant", incident_id)
                    entry = storage.get_json(record_key)
                    entry["status"] = terminal
                    entry["completed_at" if terminal == "completed" else "failed_at"] = "2020-01-01T00:00:00+00:00"
                    storage.put_json(record_key, entry)
                    ended_field = "completed_at" if terminal == "completed" else "failed_at"
                    decision_key = storage.review_release_key("tenant", incident_id)
                    decision = storage.get_json(decision_key) or {"incident_id": incident_id, "status": terminal}
                    decision[ended_field] = entry[ended_field]
                    storage.put_json(decision_key, decision)
                    fence_key = storage.review_claim_key("tenant", incident_id)
                    fence = storage.get_json(fence_key)
                    fence[ended_field] = entry[ended_field]
                    storage.put_json(fence_key, fence)
                    store = IncidentStore(storage)
                    store.retention_days = 1
                    in_retention = True
                    store.apply_retention("tenant")
                elif terminal == "completed":
                    queue.mark_completed("tenant", incident_id, {})
                else:
                    queue.mark_failed("tenant", incident_id, "unavailable")

            process = ctx.Process(target=child)
            process.start()
            process.join(timeout=15)
            assert process.exitcode == 19
            restarted = IncidentQueue(storage)
            reserved_id = None
            if stage == "slot":
                slots = storage.list_keys("tenant/review_heads/")
                assert len(slots) == 1
                reserved_id = storage.get_json(slots[0])["incident_id"]
            if terminal == "failed" and stage == "marker_release":
                failed_key = storage.list_keys("tenant/queue/failed/")[0]
                failed = storage.get_json(failed_key)
                failed["failed_at"] = "2020-01-01T00:00:00+00:00"
                storage.put_json(failed_key, failed)
                store = IncidentStore(storage)
                store.retention_days = 1
                store.apply_retention("tenant")
                assert restarted.claim_next("tenant") is None
            if terminal == "failed" and stage.startswith("retention_"):
                store = IncidentStore(storage)
                store.retention_days = 1
                store.apply_retention("tenant")
            recovered = restarted.recover_stale_processing("tenant")
            if stage in ("claim", "processing"):
                assert recovered == 1
            else:
                assert recovered == 0
            claimed_before_retry = restarted.claim_next("tenant") if stage == "pending" else None
            if stage == "pending":
                assert claimed_before_retry is not None
            incident_id = restarted.enqueue("tenant", review_context)
            if stage == "slot":
                assert incident_id == reserved_id
            assert restarted.enqueue("tenant", review_context) == incident_id
            claimed = claimed_before_retry or restarted.claim_next("tenant")
            if terminal == "completed" and stage in ("terminal", "fence", "decision", "delete", "retention_index", "retention_fence", "retention_record"):
                assert claimed is None
                marker = storage.get_json(_review_marker_key(storage, "tenant", incident_id))
                assert marker["status"] == terminal
                if "context" in marker:
                    assert marker["context"] == review_context
                assert storage.list_keys("tenant/queue/pending/") == []
            else:
                assert claimed is not None
                assert claimed["incident_id"] == incident_id
                assert claimed["attempts"] == (2 if stage in ("claim", "processing") else 1)
                restarted.mark_completed("tenant", incident_id, {})
            assert restarted.claim_next("tenant") is None

    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    @pytest.mark.parametrize("held", ["pending_claim", "processing_recovery"])
    def test_retention_expires_terminal_records_preserves_active_work(self, monkeypatch, review_context, terminal, held):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("tenant", review_context)
        marker_key = _review_marker_key(storage, "tenant", incident_id)
        if held == "processing_recovery":
            assert queue.claim_next("tenant") is not None
        get = storage.get_json
        taken, release = threading.Event(), threading.Event()
        expected_status = "pending" if held == "pending_claim" else "processing"

        def snapshot(key):
            result = get(key)
            if key == marker_key and result and result.get("status") == expected_status and not taken.is_set():
                taken.set()
                assert release.wait(10)
            return result

        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", snapshot)
            with ThreadPoolExecutor(max_workers=1) as executor:
                action = queue.claim_next if held == "pending_claim" else queue.recover_stale_processing
                stale = executor.submit(action, "tenant")
                try:
                    assert taken.wait(10)
                    if held == "pending_claim":
                        assert queue.claim_next("tenant") is not None
                    if terminal == "completed":
                        queue.mark_completed("tenant", incident_id, {})
                        for key in (marker_key, storage.review_claim_key("tenant", incident_id), storage.review_release_key("tenant", incident_id)):
                            entry = get(key)
                            entry["completed_at"] = "2020-01-01T00:00:00+00:00"
                            storage.put_json(key, entry)
                        assert IncidentStore(storage).apply_retention("tenant") == 0
                        assert get(marker_key)["status"] == "completed"
                        assert "context" not in get(marker_key)
                        assert queue.enqueue("tenant", review_context) == incident_id
                    else:
                        queue.mark_failed("tenant", incident_id, "unavailable")
                        assert not storage.exists(marker_key)
                        failed_key = storage.queue_key("tenant", "failed", incident_id)
                        failed = get(failed_key)
                        assert failed["context"] == review_context
                        failed["failed_at"] = "2020-01-01T00:00:00+00:00"
                        storage.put_json(failed_key, failed)
                        terminal_record = get(storage.review_release_key("tenant", incident_id))
                        terminal_record["failed_at"] = failed["failed_at"]
                        storage.put_json(storage.review_release_key("tenant", incident_id), terminal_record)
                        # A new attempt must survive the old claimant/recovery snapshot.
                        retry_id = queue.enqueue("tenant", review_context)
                        assert retry_id != incident_id
                        assert IncidentStore(storage).apply_retention("tenant") == 1
                    assert IncidentStore(storage).apply_retention("tenant") == 0
                finally:
                    release.set()
                assert stale.result(timeout=10) == (None if held == "pending_claim" else 0)
        if terminal == "failed":
            fence = storage.get_json(storage.review_claim_key("tenant", incident_id))
            assert fence and fence["status"] == "failed"
            assert "context" not in fence
            assert queue.claim_next("tenant")["incident_id"] == retry_id
            queue.mark_completed("tenant", retry_id, {})
        assert storage.list_keys("tenant/queue/pending/") == []
        for state in ("processing", "pending"):
            context = {**review_context, "head_sha": state}
            live_id = queue.enqueue("tenant", context)
            if state == "processing":
                assert queue.claim_next("tenant")["incident_id"] == live_id
            for key in storage.list_keys("tenant/"):
                entry = storage.get_json(key)
                entry["created_at"] = "2020-01-01T00:00:00+00:00"
                if "claimed_at" in entry:
                    entry["claimed_at"] = entry["created_at"]
                storage.put_json(key, entry)
            assert IncidentStore(storage).apply_retention("tenant") == 0
        assert queue.recover_stale_processing("tenant") == 1
        assert all(queue.claim_next("tenant") is not None for _ in range(2))

    @pytest.mark.parametrize("field", ["type", "scm_platform", "repo", "change_id", "head_sha"])
    @pytest.mark.parametrize("missing", [False, True])
    def test_incomplete_review_identity_is_not_deduped(self, review_context, field, missing):
        context = dict(review_context)
        if missing:
            del context[field]
        else:
            context[field] = ""
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        assert queue.enqueue("tenant", context) != queue.enqueue("tenant", context)
        assert len(storage.list_keys("tenant/queue/pending/")) == 2
        assert storage.list_keys("tenant/review_dedupe/") == []

    @pytest.mark.parametrize("provider", ["gitlab", "bitbucket"])
    @pytest.mark.parametrize("timing", ["before", "after"])
    def test_concurrent_deliveries_survive_failed_publisher(self, monkeypatch, review_context, provider, timing):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        context = {**review_context, "scm_platform": provider}
        put = storage.put_json_if_absent
        waiting, release = threading.Event(), threading.Event()
        first = True
        lock = threading.Lock()

        def write(key, data):
            nonlocal first
            with lock:
                owner = first and "/queue/pending/" in key
                if owner:
                    first = False
            if owner:
                if timing == "after":
                    put(key, data)
                waiting.set()
                assert release.wait(10)
                raise RuntimeError("publisher failed")
            return put(key, data)

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", write)
            with ThreadPoolExecutor(max_workers=8) as executor:
                owner = executor.submit(queue.enqueue, "tenant", context)
                try:
                    assert waiting.wait(10)
                    duplicates = [executor.submit(queue.enqueue, "tenant", context) for _ in range(7)]
                    ids = [future.result(timeout=10) for future in duplicates]
                finally:
                    release.set()
                assert owner.result(timeout=10) == ids[0]
        assert len(set(ids)) == 1
        # Hold the winner's final pending snapshot while a second caller claims.
        exists = storage.exists
        terminal_key = storage.review_release_key("tenant", ids[0])
        snapshot_taken, release_snapshot = threading.Event(), threading.Event()
        owner_thread = None
        counts = {}

        def hold_claim_snapshot(key):
            nonlocal owner_thread
            entry = exists(key)
            if key == terminal_key:
                thread = threading.get_ident()
                if owner_thread is None:
                    owner_thread = thread
                counts[thread] = counts.get(thread, 0) + 1
                if thread == owner_thread and counts[thread] == 2:
                    snapshot_taken.set()
                    assert release_snapshot.wait(10)
            return entry

        with monkeypatch.context() as injection:
            injection.setattr(storage, "exists", hold_claim_snapshot)
            with ThreadPoolExecutor(max_workers=1) as executor:
                winner = executor.submit(queue.claim_next, "tenant")
                try:
                    assert snapshot_taken.wait(10)
                    assert queue.claim_next("tenant") is None
                finally:
                    release_snapshot.set()
                assert winner.result(timeout=10)["incident_id"] == ids[0]
        assert queue.claim_next("tenant") is None


@pytest.mark.parametrize("action", ["open", "reopen", "update"])
@pytest.mark.parametrize("state", ["closed", "merged"])
def test_gitlab_terminal_state_never_enqueues(gitlab_request, gitlab_payload, action, state):
    attrs = gitlab_payload["object_attributes"]
    attrs.update(action=action, state=state, oldrev="previous")
    with patch("api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")) as enqueue:
        response = gitlab_request(gitlab_payload)
        assert response.json()["status"] == "ignored"
        assert enqueue.call_count == 0
        attrs["state"] = "opened"
        assert gitlab_request(gitlab_payload).json()["status"] == "queued"
        assert enqueue.call_count == 1


@pytest.mark.parametrize("terminal", ["completed", "failed"])
def test_terminal_cleanup_retries_from_durable_context(monkeypatch, review_context, terminal):
    storage = MemoryStorage()
    queue = IncidentQueue(storage)
    incident_id = queue.enqueue("tenant", review_context)
    marker_key = queue.claim_next("tenant")["review_key"]
    put = storage.put_json
    def fail_fence(key, data):
        if "/review_claims/" in key:
            raise RuntimeError("fence write failed")
        return put(key, data)
    failure = None
    with monkeypatch.context() as injection:
        injection.setattr(storage, "put_json", fail_fence)
        try:
            if terminal == "completed":
                queue.mark_completed("tenant", incident_id, {})
            else:
                queue.mark_failed("tenant", incident_id, "unavailable")
        except RuntimeError as error:
            failure = error
    assert failure is not None
    assert queue.enqueue("tenant", review_context) == incident_id
    if terminal == "completed":
        queue.mark_completed("tenant", incident_id, {})
        assert storage.get_json(marker_key).get("context") == review_context
    else:
        queue.mark_failed("tenant", incident_id, "unavailable")
        assert not storage.exists(marker_key)
        failed_key = storage.queue_key("tenant", "failed", incident_id)
        assert storage.get_json(failed_key).get("context") == review_context
    assert queue.claim_next("tenant") is None
    assert storage.list_keys("tenant/queue/pending/") == []


@pytest.mark.parametrize("terminal", ["completed", "failed"])
def test_retention_cleans_interrupted_terminal_transition(monkeypatch, review_context, terminal):
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
    storage = MemoryStorage()
    queue = IncidentQueue(storage)
    incident_id = queue.enqueue("tenant", review_context)
    marker_key = queue.claim_next("tenant")["review_key"]
    entry = storage.get_json(marker_key)
    entry.update(status=terminal)
    entry["completed_at" if terminal == "completed" else "failed_at"] = "2020-01-01T00:00:00+00:00"
    if terminal == "failed":
        storage.put_json(storage.queue_key("tenant", "failed", incident_id), entry)
    storage.put_json(marker_key, entry)
    if terminal == "completed":
        storage.put_json_if_absent(storage.review_release_key("tenant", incident_id),
                                   {"incident_id": incident_id, "status": terminal, "completed_at": entry["completed_at"]})
    deleted = IncidentStore(storage).apply_retention("tenant")
    if terminal == "completed":
        assert deleted == 1
        assert storage.get_json(marker_key)["status"] == "completed"
        assert "context" not in storage.get_json(marker_key)
        assert queue.enqueue("tenant", review_context) == incident_id
    else:
        assert deleted == 0
        assert storage.get_json(marker_key)["status"] == "failed"
        assert storage.exists(storage.queue_key("tenant", "failed", incident_id))
        assert queue.recover_stale_processing("tenant") == 0
        assert IncidentStore(storage).apply_retention("tenant") == 1
        assert not storage.exists(marker_key)
        assert storage.get_json(storage.review_claim_key("tenant", incident_id))["status"] == "failed"
    assert storage.list_keys("tenant/queue/pending/") == []
    assert queue.claim_next("tenant") is None


@pytest.mark.parametrize("event", ["Push Hook", "Note Hook", "Tag Push Hook"])
def test_gitlab_event_filter_has_positive_control(gitlab_request, gitlab_payload, event):
    with patch("api.server.enqueue_incident", new=AsyncMock(return_value="INC-review")) as enqueue:
        assert gitlab_request(gitlab_payload, event).json()["status"] == "ignored"
        assert enqueue.call_count == 0
        assert gitlab_request(gitlab_payload).json()["status"] == "queued"
        assert enqueue.call_count == 1


@pytest.mark.parametrize("status", ["pending", "processing", "completed", "failed"])
def test_legacy_record_replay_requires_published_active_work(monkeypatch, review_context, status):
    storage = MemoryStorage()
    queue = IncidentQueue(storage)
    marker, legacy_key = _seed_legacy_review(storage, "tenant", review_context, status)
    incident_id = marker["incident_id"]
    def fail_index(key, data):
        raise RuntimeError("active index unavailable")
    failure = None
    with monkeypatch.context() as injection:
        injection.setattr(storage, "put_json_if_absent", fail_index)
        try:
            queue.enqueue("tenant", review_context)
        except RuntimeError as error:
            failure = error
    assert (failure is not None) == (status in ("pending", "processing"))
    assert queue.enqueue("tenant", review_context) == incident_id
    if status == "pending":
        assert queue.claim_next("tenant")["incident_id"] == incident_id
    elif status == "processing":
        assert queue.recover_stale_processing("tenant") == 1
        assert queue.claim_next("tenant")["incident_id"] == incident_id
    else:
        assert queue.claim_next("tenant") is None


@pytest.mark.parametrize("status", ["pending", "processing"])
def test_retention_preserves_legacy_active_reviews(monkeypatch, review_context, status):
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
    storage = MemoryStorage()
    legacy_key = storage.queue_key("tenant", "reviews", "INC-legacy")
    entry = {"incident_id": "INC-legacy", "org_id": "tenant", "context": review_context,
             "status": status, "created_at": "2020-01-01T00:00:00+00:00"}
    storage.put_json(legacy_key, entry)
    assert IncidentStore(storage).apply_retention("tenant") == 0
    assert storage.get_json(legacy_key) == entry


def test_retention_aborts_on_s3_fence_head_failure(monkeypatch, review_context):
    from storage.s3_storage import S3Storage

    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
    storage = MemoryStorage()
    queue = IncidentQueue(storage)
    incident_id = queue.enqueue("tenant", review_context)
    marker_key = queue.claim_next("tenant")["review_key"]
    queue.mark_failed("tenant", incident_id, "unavailable")
    failed_key = storage.queue_key("tenant", "failed", incident_id)
    entry = storage.get_json(failed_key)
    entry["failed_at"] = "2020-01-01T00:00:00+00:00"
    storage.put_json(failed_key, entry)
    retry_id = queue.enqueue("tenant", review_context)
    marker_key = _review_marker_key(storage, "tenant", retry_id)
    retry_marker = storage.get_json(marker_key)
    remove = storage.delete
    fail_head = True

    class Client:
        def head_object(self, Bucket, Key):
            assert Bucket == "test-bucket"
            if fail_head and Key == storage.queue_key("tenant", "pending", incident_id):
                raise TimeoutError("HEAD unavailable")
            if Key not in storage._objects:
                raise Exception("404")
            return {}

        def delete_object(self, Bucket, Key):
            assert Bucket == "test-bucket"
            remove(Key)

    storage.bucket = "test-bucket"
    storage._client = Client()
    storage.exists = S3Storage.exists.__get__(storage)
    storage.delete = S3Storage.delete.__get__(storage)
    failure = None
    try:
        IncidentStore(storage).apply_retention("tenant")
    except TimeoutError as error:
        failure = error
    assert failure is not None
    assert storage.get_json(failed_key) == entry
    assert storage.get_json(marker_key) == retry_marker
    assert queue.enqueue("tenant", review_context) == retry_id
    claimed = queue.claim_next("tenant")
    assert claimed and claimed["incident_id"] == retry_id
    queue.mark_completed("tenant", retry_id, {})
    fail_head = False
    assert IncidentStore(storage).apply_retention("tenant") == 1
    assert not storage.exists(failed_key)
    assert storage.get_json(marker_key)["status"] == "completed"
    assert storage.list_keys("tenant/queue/") == []


class TestReviewFailureRetry:
    @pytest.mark.parametrize("terminal", ["failed", "completed"])
    def test_terminal_policy_through_bitbucket_webhook(
        self, bitbucket_request, bitbucket_payload, review_queue, terminal
    ):
        first = bitbucket_request(bitbucket_payload)
        assert first.status_code == 200
        incident_id = first.json()["incident_id"]
        assert review_queue.claim_next("tenant-ember")["incident_id"] == incident_id
        if terminal == "failed":
            review_queue.mark_failed("tenant-ember", incident_id, "review unavailable")
        else:
            review_queue.mark_completed("tenant-ember", incident_id, {})
        second = bitbucket_request(bitbucket_payload, "pullrequest:updated")
        third = bitbucket_request(bitbucket_payload, "pullrequest:updated")
        assert second.status_code == third.status_code == 200
        assert second.json() == third.json()
        claimed = review_queue.claim_next("tenant-ember")
        if terminal == "failed":
            assert claimed is not None
            assert claimed["incident_id"] == second.json()["incident_id"] != incident_id
            assert claimed["context"]["head_sha"] == "commit-juniper"
            failed = review_queue.storage.get_json(
                review_queue.storage.queue_key("tenant-ember", "failed", incident_id)
            )
            assert failed and failed["status"] == "failed"
            assert failed["error"] == "review unavailable"
        else:
            assert claimed is None
            assert second.json() == first.json()
        assert review_queue.claim_next("tenant-ember") is None

    @pytest.mark.parametrize("terminal", ["failed", "completed"])
    def test_terminal_policy_direct_gitlab_concurrent_deliveries(self, review_context, terminal):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        context = {**review_context, "scm_platform": "gitlab"}
        incident_id = queue.enqueue("tenant", context)
        assert queue.claim_next("tenant")["incident_id"] == incident_id
        if terminal == "failed":
            queue.mark_failed("tenant", incident_id, "unavailable")
        else:
            queue.mark_completed("tenant", incident_id, {})
        with ThreadPoolExecutor(max_workers=8) as executor:
            ids = list(executor.map(lambda _: queue.enqueue("tenant", context), range(8)))
        assert len(set(ids)) == 1
        assert queue.enqueue("tenant", context) == ids[0]
        claimed = queue.claim_next("tenant")
        if terminal == "failed":
            assert claimed is not None
            assert claimed["incident_id"] == ids[0] != incident_id
            assert claimed["context"] == context
        else:
            assert claimed is None
            assert ids[0] == incident_id
        assert queue.claim_next("tenant") is None

    @pytest.mark.parametrize("resume", ["transition", "recovery"])
    def test_failed_marker_delete_error_keeps_failed_record_and_dedupe(self, monkeypatch, review_context, resume):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("tenant", review_context)
        claimed = queue.claim_next("tenant")
        marker_key = claimed["review_key"]
        failed_key = storage.queue_key("tenant", "failed", incident_id)
        delete = storage.delete

        def fail_marker_delete(key):
            if key == marker_key:
                raise RuntimeError("marker delete unavailable")
            return delete(key)

        failure = None
        with monkeypatch.context() as injection:
            injection.setattr(storage, "delete", fail_marker_delete)
            try:
                queue.mark_failed("tenant", incident_id, "review unavailable")
            except RuntimeError as error:
                failure = error
        assert failure is not None
        assert str(failure) == "marker delete unavailable"
        failed = storage.get_json(failed_key)
        assert failed and failed["status"] == "failed"
        assert failed["context"] == review_context
        assert failed["error"] == "review unavailable"
        assert storage.exists(marker_key)
        assert storage.get_json(marker_key)["status"] == "failed"
        assert queue.enqueue("tenant", review_context) == incident_id
        assert queue.claim_next("tenant") is None
        # Retry cleanup using persisted failure while the terminal fence stays in place.
        if resume == "transition":
            queue.mark_failed("tenant", incident_id, "review unavailable")
        else:
            assert queue.recover_stale_processing("tenant") == 0
        assert not storage.exists(marker_key)
        assert storage.get_json(failed_key) == failed
        retry_id = queue.enqueue("tenant", review_context)
        assert queue.enqueue("tenant", review_context) == retry_id
        assert queue.claim_next("tenant")["incident_id"] == retry_id != incident_id
        assert queue.claim_next("tenant") is None

    def test_failed_record_write_precedes_marker_delete(self, monkeypatch, review_context):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("tenant", review_context)
        marker_key = queue.claim_next("tenant")["review_key"]
        failed_key = storage.queue_key("tenant", "failed", incident_id)
        put, delete = storage.put_json, storage.delete
        order = []

        def record_write(key, data):
            result = put(key, data)
            if key == failed_key:
                order.append("failed persisted")
            return result

        def record_delete(key):
            if key == marker_key:
                failed = storage.get_json(failed_key) or {}
                assert failed.get("status") == "failed"
                assert failed.get("context") == review_context
                order.append("marker deleted")
            return delete(key)

        monkeypatch.setattr(storage, "put_json", record_write)
        monkeypatch.setattr(storage, "delete", record_delete)
        queue.mark_failed("tenant", incident_id, "unavailable")
        assert order == ["failed persisted", "marker deleted"]
        assert storage.get_json(failed_key)["error"] == "unavailable"
        assert not storage.exists(marker_key)

    def test_old_failed_transition_cannot_release_new_attempt(self, review_context):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        queue.claim_next("tenant")
        queue.mark_failed("tenant", old_id, "first failure")
        new_id = queue.enqueue("tenant", review_context)
        assert new_id != old_id
        # A retry of the old transition must retain the new reservation and work.
        queue.mark_failed("tenant", old_id, "first failure")
        assert queue.enqueue("tenant", review_context) == new_id
        claimed = queue.claim_next("tenant")
        assert claimed and claimed["incident_id"] == new_id
        queue.mark_failed("tenant", old_id, "first failure")
        assert queue.enqueue("tenant", review_context) == new_id
        assert queue.claim_next("tenant") is None
        assert storage.get_json(storage.queue_key("tenant", "failed", old_id))["error"] == "first failure"

    def test_non_review_failure_keeps_original_queue_behavior(self, monkeypatch):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        context = {"type": "server", "host": "203.0.113.7"}
        incident_id = queue.enqueue("tenant", context)
        claimed = queue.claim_next("tenant")
        deletes = []
        delete = storage.delete
        def record_delete(key):
            deletes.append(key)
            return delete(key)
        monkeypatch.setattr(storage, "delete", record_delete)
        queue.mark_failed("tenant", incident_id, "unavailable")
        failed = storage.get_json(storage.queue_key("tenant", "failed", incident_id))
        assert failed["context"] == context
        assert failed["attempts"] == claimed["attempts"]
        assert failed["status"] == "failed" and failed["error"] == "unavailable"
        assert deletes == [storage.queue_key("tenant", "processing", incident_id)]
        assert storage.list_keys("tenant/review_dedupe/") == []
        assert storage.list_keys("tenant/review_claims/") == []
        assert queue.claim_next("tenant") is None

    def test_completed_head_dedupes_after_retention(self, monkeypatch, review_context):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("tenant", review_context)
        marker_key = queue.claim_next("tenant")["review_key"]
        queue.mark_completed("tenant", incident_id, {})
        for key in (marker_key, storage.review_claim_key("tenant", incident_id), storage.review_release_key("tenant", incident_id)):
            entry = storage.get_json(key)
            entry["completed_at"] = "2020-01-01T00:00:00+00:00"
            storage.put_json(key, entry)
        ordinary_key = storage.queue_key("tenant", "completed", "INC-expired")
        storage.put_json(ordinary_key, {"completed_at": "2020-01-01T00:00:00+00:00"})
        IncidentStore(storage).apply_retention("tenant")
        assert not storage.exists(ordinary_key)
        assert storage.exists(marker_key)
        assert queue.enqueue("tenant", review_context) == incident_id
        assert queue.enqueue("tenant", review_context) == incident_id
        assert queue.claim_next("tenant") is None
        assert queue.recover_stale_processing("tenant") == 0


    def test_stale_failed_index_cannot_resurrect_released_marker(self, monkeypatch, review_context):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        index_key = storage.queue_key("tenant", "pending", old_id)
        marker_key = storage.get_json(index_key)["review_key"]
        get = storage.get_json
        taken, release = threading.Event(), threading.Event()

        def hold_index(key):
            entry = get(key)
            if key == index_key and entry and not taken.is_set():
                taken.set()
                assert release.wait(10)
            return entry

        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", hold_index)
            with ThreadPoolExecutor(max_workers=1) as executor:
                stale = executor.submit(queue.claim_next, "tenant")
                try:
                    assert taken.wait(10)
                    assert queue.claim_next("tenant")["incident_id"] == old_id
                    queue.mark_failed("tenant", old_id, "unavailable")
                    assert not storage.exists(marker_key)
                finally:
                    release.set()
                assert stale.result(timeout=10) is None
        assert not storage.exists(marker_key)
        new_id = queue.enqueue("tenant", review_context)
        assert queue.enqueue("tenant", review_context) == new_id != old_id
        assert queue.claim_next("tenant")["incident_id"] == new_id
        assert queue.claim_next("tenant") is None


    @pytest.mark.parametrize("successor_state", ["pending", "processing"])
    def test_delayed_marker_publication_cannot_execute_terminal_attempt_or_disturb_successor(self, monkeypatch, review_context, successor_state):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        put = storage.put_json_if_absent
        waiting, release = threading.Event(), threading.Event()

        def hold_marker(key, data):
            if "/review_dedupe/" in key and not waiting.is_set():
                waiting.set()
                assert release.wait(10)
            return put(key, data)

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", hold_marker)
            with ThreadPoolExecutor(max_workers=1) as executor:
                publisher = executor.submit(queue.enqueue, "tenant", review_context)
                try:
                    assert waiting.wait(10)
                    old_id = queue.enqueue("tenant", review_context)
                    early = queue.claim_next("tenant")
                    assert early is not None and early["incident_id"] == old_id
                    queue.mark_failed("tenant", old_id, "unavailable")
                    assert not storage.exists(early["review_key"])
                    new_id = queue.enqueue("tenant", review_context)
                    assert new_id != old_id
                    new_marker = _review_marker_key(storage, "tenant", new_id)
                    if successor_state == "processing":
                        assert queue.claim_next("tenant")["incident_id"] == new_id
                    successor = storage.get_json(new_marker)
                    successor_slot = storage.get_json(successor["review_slot"])
                    successor_index = storage.get_json(storage.queue_key("tenant", "pending", new_id))
                    successor_claim = storage.get_json(storage.review_claim_key("tenant", new_id))
                finally:
                    release.set()
                assert publisher.result(timeout=10) == old_id
        assert storage.get_json(new_marker) == successor
        assert storage.get_json(successor["review_slot"]) == successor_slot
        assert storage.get_json(storage.queue_key("tenant", "pending", new_id)) == successor_index
        assert storage.get_json(storage.review_claim_key("tenant", new_id)) == successor_claim
        assert queue.enqueue("tenant", review_context) == new_id
        next_claim = queue.claim_next("tenant")
        old_claimable = next_claim is not None and next_claim["incident_id"] == old_id
        print(f"DELAYED_MARKER successor={successor_state} restored={storage.exists(early['review_key'])} "
              f"old_claimable={old_claimable} successor_preserved={storage.get_json(new_marker) is not None}")
        assert not old_claimable
        if successor_state == "pending":
            assert next_claim and next_claim["incident_id"] == new_id
        else:
            assert next_claim is None
        assert queue.claim_next("tenant") is None

    def test_stale_failure_read_cannot_recreate_marker(self, monkeypatch, review_context):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        marker_key = _review_marker_key(storage, "tenant", old_id)
        failed_key = storage.queue_key("tenant", "failed", old_id)
        get = storage.get_json
        waiting, release = threading.Event(), threading.Event()

        def hold_failure_read(key):
            entry = get(key)
            if key == failed_key and entry is None and not waiting.is_set():
                waiting.set()
                assert release.wait(10)
            return entry

        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", hold_failure_read)
            with ThreadPoolExecutor(max_workers=1) as executor:
                stale = executor.submit(queue.claim_next, "tenant")
                try:
                    assert waiting.wait(10)
                    assert queue.claim_next("tenant")["incident_id"] == old_id
                    queue.mark_failed("tenant", old_id, "unavailable")
                finally:
                    release.set()
                assert stale.result(timeout=10) is None
        assert not storage.exists(marker_key)
        new_id = queue.enqueue("tenant", review_context)
        assert queue.enqueue("tenant", review_context) == new_id != old_id
        assert queue.claim_next("tenant")["incident_id"] == new_id
        assert queue.claim_next("tenant") is None

    @pytest.mark.parametrize("new_attempt", [False, True])
    def test_expired_failed_attempt_cleans_own_stale_index(self, monkeypatch, review_context, new_attempt):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        marker_key = queue.claim_next("tenant")["review_key"]
        index_key = storage.queue_key("tenant", "pending", old_id)
        failed_key = storage.queue_key("tenant", "failed", old_id)
        delete = storage.delete

        def stop_index_cleanup(key):
            if key == index_key:
                raise RuntimeError("index cleanup interrupted")
            return delete(key)

        with monkeypatch.context() as injection:
            injection.setattr(storage, "delete", stop_index_cleanup)
            with pytest.raises(RuntimeError, match="index cleanup interrupted"):
                queue.mark_failed("tenant", old_id, "unavailable")
        assert not storage.exists(marker_key)
        assert storage.exists(index_key)
        failed = storage.get_json(failed_key)
        failed["failed_at"] = "2020-01-01T00:00:00+00:00"
        storage.put_json(failed_key, failed)
        if new_attempt:
            retry_id = queue.enqueue("tenant", review_context)
            assert retry_id != old_id
        IncidentStore(storage).apply_retention("tenant")
        assert not storage.exists(index_key)
        assert not storage.exists(failed_key)
        assert queue.recover_stale_processing("tenant") == 0
        claimed = queue.claim_next("tenant")
        if new_attempt:
            assert claimed and claimed["incident_id"] == retry_id
        else:
            assert claimed is None
            retry_id = queue.enqueue("tenant", review_context)
            assert queue.enqueue("tenant", review_context) == retry_id != old_id
            assert queue.claim_next("tenant")["incident_id"] == retry_id
        assert queue.claim_next("tenant") is None

    @pytest.mark.parametrize("cleanup", ["index", "history"])
    def test_failed_history_expiry_preserves_evidence_on_cleanup_error(self, monkeypatch, review_context, cleanup):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        entry = queue.claim_next("tenant")
        index_key = storage.queue_key("tenant", "pending", old_id)
        remove = storage.delete
        def stop_index_cleanup(key):
            if key == index_key:
                raise RuntimeError("index cleanup interrupted")
            return remove(key)
        with monkeypatch.context() as injection:
            injection.setattr(storage, "delete", stop_index_cleanup)
            with pytest.raises(RuntimeError, match="index cleanup interrupted"):
                queue.mark_failed("tenant", old_id, "unavailable")
        failed_key = storage.queue_key("tenant", "failed", old_id)
        failed = storage.get_json(failed_key)
        failed["failed_at"] = "2020-01-01T00:00:00+00:00"
        storage.put_json(failed_key, failed)
        target = (storage.queue_key("tenant", "pending", old_id) if cleanup == "index"
                  else failed_key)
        delete = storage.delete

        def fail_cleanup(key):
            if key == target:
                raise RuntimeError("failed cleanup unavailable")
            return delete(key)

        failure = None
        with monkeypatch.context() as injection:
            injection.setattr(storage, "delete", fail_cleanup)
            try:
                IncidentStore(storage).apply_retention("tenant")
            except RuntimeError as error:
                failure = error
        assert failure is not None
        assert storage.get_json(failed_key) == failed
        IncidentStore(storage).apply_retention("tenant")
        assert not storage.exists(failed_key)
        assert not storage.exists(entry["review_key"])
        assert queue.claim_next("tenant") is None


    @pytest.mark.parametrize("terminal", ["failed", "completed"])
    def test_delayed_pending_publish_retires_terminal_index(self, monkeypatch, review_context, terminal):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        put = storage.put_json_if_absent
        waiting, release = threading.Event(), threading.Event()

        def hold_pending(key, data):
            if "/queue/pending/" in key and not waiting.is_set():
                waiting.set()
                assert release.wait(10)
            return put(key, data)

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", hold_pending)
            with ThreadPoolExecutor(max_workers=1) as executor:
                publisher = executor.submit(queue.enqueue, "tenant", review_context)
                try:
                    assert waiting.wait(10)
                    old_id = queue.enqueue("tenant", review_context)
                    assert queue.claim_next("tenant")["incident_id"] == old_id
                    if terminal == "failed":
                        queue.mark_failed("tenant", old_id, "unavailable")
                    else:
                        queue.mark_completed("tenant", old_id, {})
                finally:
                    release.set()
                assert publisher.result(timeout=10) == old_id
        assert storage.list_keys("tenant/queue/pending/") == []
        new_id = queue.enqueue("tenant", review_context)
        assert queue.enqueue("tenant", review_context) == new_id
        claimed = queue.claim_next("tenant")
        if terminal == "failed":
            assert new_id != old_id
            assert claimed and claimed["incident_id"] == new_id
        else:
            assert new_id == old_id
            assert claimed is None
        assert queue.claim_next("tenant") is None


    @pytest.mark.parametrize("phase", ["failed_history", "head_marker"])
    def test_retention_snapshot_cannot_delete_new_attempt_marker(self, monkeypatch, review_context, phase):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        marker_key = queue.claim_next("tenant")["review_key"]
        failed_key = storage.queue_key("tenant", "failed", old_id)
        delete = storage.delete

        def hold_failed_marker(key):
            if key == marker_key:
                raise RuntimeError("marker release interrupted")
            return delete(key)

        with monkeypatch.context() as injection:
            injection.setattr(storage, "delete", hold_failed_marker)
            with pytest.raises(RuntimeError, match="marker release interrupted"):
                queue.mark_failed("tenant", old_id, "unavailable")
        marker = storage.get_json(marker_key)
        marker["failed_at"] = "2020-01-01T00:00:00+00:00"
        storage.put_json(marker_key, marker)
        if phase == "failed_history":
            failed = storage.get_json(failed_key)
            failed["failed_at"] = marker["failed_at"]
            storage.put_json(failed_key, failed)
        get = storage.get_json
        taken, release = threading.Event(), threading.Event()

        target = storage.review_release_key("tenant", old_id) if phase == "failed_history" else marker_key
        def snapshot(key):
            entry = get(key)
            if key == target and not taken.is_set():
                taken.set()
                assert release.wait(10)
            return entry

        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", snapshot)
            with ThreadPoolExecutor(max_workers=1) as executor:
                retention = executor.submit(IncidentStore(storage).apply_retention, "tenant")
                try:
                    assert taken.wait(10)
                    queue.mark_failed("tenant", old_id, "unavailable")
                    new_id = queue.enqueue("tenant", review_context)
                    assert new_id != old_id
                    new_marker = _review_marker_key(storage, "tenant", new_id)
                finally:
                    release.set()
                retention.result(timeout=10)
        current = storage.get_json(new_marker) or {}
        assert current.get("incident_id") == new_id
        assert queue.enqueue("tenant", review_context) == new_id
        claimed = queue.claim_next("tenant")
        assert claimed and claimed["incident_id"] == new_id
        assert queue.claim_next("tenant") is None


class TestReviewFixRoundOne:
    @pytest.mark.parametrize("snapshot", [1, 2])
    @pytest.mark.parametrize("new_phase", ["pending", "processing"])
    def test_stale_failure_cleanup_cannot_change_new_attempt(self, monkeypatch, review_context, snapshot, new_phase):
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        old_marker = queue.claim_next("tenant")["review_key"]
        get = storage.get_json
        waiting, release = threading.Event(), threading.Event()
        actor_thread = None
        reads = 0
        changed = []
        put, create, delete = storage.put_json, storage.put_json_if_absent, storage.delete

        def record_mutation(operation, key, *args):
            if threading.get_ident() == actor_thread:
                changed.append(key)
            return operation(key, *args)

        def held_read(key):
            nonlocal reads
            entry = get(key)
            if key == old_marker and threading.get_ident() == actor_thread and entry:
                reads += 1
                if reads == snapshot:
                    waiting.set()
                    assert release.wait(10)
            return entry

        def old_actor():
            nonlocal actor_thread
            actor_thread = threading.get_ident()
            queue.mark_failed("tenant", old_id, "unavailable")

        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", held_read)
            injection.setattr(storage, "put_json", lambda key, data: record_mutation(put, key, data))
            injection.setattr(storage, "put_json_if_absent", lambda key, data: record_mutation(create, key, data))
            injection.setattr(storage, "delete", lambda key: record_mutation(delete, key))
            with ThreadPoolExecutor(max_workers=1) as executor:
                stale = executor.submit(old_actor)
                try:
                    assert waiting.wait(10)
                    queue.mark_failed("tenant", old_id, "unavailable")
                    new_id = queue.enqueue("tenant", review_context)
                    assert new_id != old_id
                    new_marker = _review_marker_key(storage, "tenant", new_id)
                    if new_phase == "processing":
                        assert queue.claim_next("tenant")["incident_id"] == new_id
                finally:
                    release.set()
                stale.result(timeout=10)
        marker = storage.get_json(new_marker) or {}
        preserved = marker.get("incident_id") == new_id
        third_id = queue.enqueue("tenant", review_context)
        third_claim = queue.claim_next("tenant")
        old_failure = storage.get_json(storage.queue_key("tenant", "failed", old_id)) or {}
        print(f"RACE snapshot={snapshot} new_phase={new_phase} marker_preserved={preserved} "
              f"third_is_new_attempt={third_id != new_id} third_claimed={third_claim is not None} "
              f"old_failure_survives={old_failure.get('status') == 'failed'}")
        assert preserved
        dependencies = {new_marker, storage.queue_key("tenant", "pending", new_id),
                        storage.review_claim_key("tenant", new_id),
                        storage.org_prefix("tenant", "review_releases", f"{new_id}.json")}
        if marker.get("review_slot"):
            dependencies.add(marker["review_slot"])
        assert dependencies.isdisjoint(changed)
        assert third_id == new_id
        if new_phase == "pending":
            assert third_claim and third_claim["incident_id"] == new_id
        else:
            assert third_claim is None
        assert old_failure["status"] == "failed" and old_failure["context"] == review_context

    @pytest.mark.asyncio
    @pytest.mark.parametrize("state", ["pending", "processing", "completed", "failed"])
    async def test_startup_adopts_only_active_legacy_reviews(self, monkeypatch, tmp_path, review_context, state):
        import api.server as server

        storage = RecordingStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-adopt", review_context, state)
        queue = IncidentQueue(storage)
        monkeypatch.setattr(server, "incident_queue", queue)
        monkeypatch.setattr(server, "_queue_worker_loop", AsyncMock())
        monkeypatch.setattr(server, "_retention_loop", AsyncMock())
        monkeypatch.setenv("BACKGROUND_WORKER_LOCK", str(tmp_path / "worker.lock"))
        async with server.lifespan(server.app):
            if state in ("pending", "processing"):
                recovered = queue.recover_stale_processing("tenant-adopt")
                if state == "processing":
                    assert recovered == 1
                claimed = queue.claim_next("tenant-adopt")
                assert claimed is not None
                assert claimed["incident_id"] == entry["incident_id"]
                assert claimed["context"] == review_context
                assert claimed["attempts"] == (2 if state == "processing" else 1)
                queue.mark_completed("tenant-adopt", claimed["incident_id"], {})
                assert not storage.exists(legacy_key)
            else:
                assert queue.claim_next("tenant-adopt") is None
                assert storage.get_json(legacy_key) == entry
                assert storage.list_keys("tenant-adopt/review_heads/") == []
                assert storage.list_keys("tenant-adopt/review_dedupe/") == []
        startup_scans = storage.listings.count("")
        assert startup_scans == 1
        # A repeated lifespan in this process must not repeat adoption's scan.
        async with server.lifespan(server.app):
            pass
        assert storage.listings.count("") == startup_scans
        storage.reads.clear()
        queue.list_pending_org_ids()
        assert queue.recover_stale_processing("tenant-adopt") == 0
        assert queue.claim_next("tenant-adopt") is None
        assert storage.reads == []

    @pytest.mark.parametrize("state", ["pending", "processing"])
    def test_concurrent_adoption_converges_on_one_legacy_attempt(self, monkeypatch, review_context, state):
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-adopt", review_context, state)
        queues = [IncidentQueue(storage), IncidentQueue(storage)]
        assert all(callable(getattr(queue, "adopt_legacy_reviews", None)) for queue in queues)
        get = storage.get_json
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        reads = 0

        def read_together(key):
            nonlocal reads
            result = get(key)
            hold = False
            if key == legacy_key and result:
                with lock:
                    reads += 1
                    hold = reads <= 2
            if hold:
                barrier.wait(timeout=10)
            return result

        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", read_together)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda queue: queue.adopt_legacy_reviews(), queues))
        assert all(result >= 0 for result in results)
        assert len(storage.list_keys("tenant-adopt/queue/pending/")) == 1
        assert queues[0].adopt_legacy_reviews() == 0
        queues[0].recover_stale_processing("tenant-adopt")
        claimed = queues[0].claim_next("tenant-adopt")
        assert claimed and claimed["incident_id"] == entry["incident_id"]
        assert queues[1].claim_next("tenant-adopt") is None

    def test_interrupted_adoption_resumes_without_another_attempt(self, monkeypatch, review_context):
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-adopt", review_context, "pending")
        queue = IncidentQueue(storage)
        assert callable(getattr(queue, "adopt_legacy_reviews", None))
        delete = storage.delete
        def fail_source_delete(key):
            if key == legacy_key:
                raise RuntimeError("adoption cleanup unavailable")
            return delete(key)
        with monkeypatch.context() as injection:
            injection.setattr(storage, "delete", fail_source_delete)
            with pytest.raises(RuntimeError, match="adoption cleanup unavailable"):
                queue.adopt_legacy_reviews()
        assert storage.exists(legacy_key)
        pending_key = storage.queue_key("tenant-adopt", "pending", entry["incident_id"])
        assert (storage.get_json(pending_key) or {}).get("incident_id") == entry["incident_id"]
        restarted = IncidentQueue(storage)
        restarted.adopt_legacy_reviews()
        claimed = restarted.claim_next("tenant-adopt")
        assert claimed and claimed["incident_id"] == entry["incident_id"]
        assert restarted.claim_next("tenant-adopt") is None
        assert not storage.exists(legacy_key)

    def test_processing_legacy_index_failure_preserves_source(self, monkeypatch, review_context):
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-adopt", review_context, "processing")
        queue = IncidentQueue(storage)
        create = storage.put_json_if_absent
        pending_key = storage.queue_key("tenant-adopt", "pending", entry["incident_id"])

        def fail_pending(key, data):
            if key == pending_key:
                raise RuntimeError("legacy index unavailable")
            return create(key, data)

        failure = None
        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json_if_absent", fail_pending)
            try:
                queue.adopt_legacy_reviews()
            except RuntimeError as error:
                failure = error
        assert storage.get_json(legacy_key) == entry
        assert failure is not None
        assert not storage.exists(pending_key)
        restarted = IncidentQueue(storage)
        assert restarted.adopt_legacy_reviews() == 1
        assert restarted.recover_stale_processing("tenant-adopt") == 1
        claimed = restarted.claim_next("tenant-adopt")
        assert claimed and claimed["incident_id"] == entry["incident_id"]
        assert restarted.claim_next("tenant-adopt") is None

    @pytest.mark.parametrize("new_phase", ["pending", "processing"])
    def test_late_adoption_cannot_clobber_new_attempt(self, monkeypatch, review_context, new_phase):
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-adopt", review_context, "pending")
        late, active = IncidentQueue(storage), IncidentQueue(storage)
        assert callable(getattr(late, "adopt_legacy_reviews", None))
        get = storage.get_json
        waiting, release = threading.Event(), threading.Event()
        def held_legacy(key):
            result = get(key)
            if key == legacy_key and result and not waiting.is_set():
                waiting.set()
                assert release.wait(10)
            return result
        with monkeypatch.context() as injection:
            injection.setattr(storage, "get_json", held_legacy)
            with ThreadPoolExecutor(max_workers=1) as executor:
                adoption = executor.submit(late.adopt_legacy_reviews)
                try:
                    assert waiting.wait(10)
                    active.adopt_legacy_reviews()
                    assert active.claim_next("tenant-adopt")["incident_id"] == entry["incident_id"]
                    active.mark_failed("tenant-adopt", entry["incident_id"], "unavailable")
                    new_id = active.enqueue("tenant-adopt", review_context)
                    assert new_id != entry["incident_id"]
                    if new_phase == "processing":
                        assert active.claim_next("tenant-adopt")["incident_id"] == new_id
                finally:
                    release.set()
                adoption.result(timeout=10)
        assert active.enqueue("tenant-adopt", review_context) == new_id
        found = active.claim_next("tenant-adopt")
        if new_phase == "pending":
            assert found and found["incident_id"] == new_id
        else:
            assert found is None


    def test_terminal_fences_and_lineage_survive_payload_retention(self, monkeypatch, review_context):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        queue = IncidentQueue(storage)
        old_id = queue.enqueue("tenant", review_context)
        claimed = queue.claim_next("tenant")
        snapshot = {**claimed, "status": "pending"}
        queue.mark_failed("tenant", old_id, "unavailable")
        release_key = storage.review_release_key("tenant", old_id)
        fence_key = storage.review_claim_key("tenant", old_id)
        failed_key = storage.queue_key("tenant", "failed", old_id)
        for key in (failed_key, fence_key, release_key):
            entry = storage.get_json(key)
            entry["failed_at"] = "2020-01-01T00:00:00+00:00"
            storage.put_json(key, entry)
        IncidentStore(storage).apply_retention("tenant")
        assert storage.exists(fence_key)
        assert "context" not in storage.get_json(fence_key)
        assert storage.exists(release_key)
        assert storage.exists(claimed["review_slot"])
        assert not storage.exists(failed_key)
        new_id = queue.enqueue("tenant", review_context)
        assert queue.claim_next("tenant")["incident_id"] == new_id != old_id
        storage.put_json(storage.queue_key("tenant", "pending", old_id), snapshot)
        assert queue.claim_next("tenant") is None
        assert queue.enqueue("tenant", review_context) == new_id
        assert storage.exists(fence_key)

    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    def test_legacy_lifecycle_claim_payload_expires_after_two_retention_passes(self, monkeypatch, review_context, terminal):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-legacy", review_context, terminal)
        incident_id = entry["incident_id"]
        claim_key = storage.review_claim_key("tenant-legacy", incident_id)
        claim = storage.get_json(claim_key)
        assert claim["status"] == "processing" and claim["context"] == review_context
        assert IncidentQueue(storage).adopt_legacy_reviews() == 0
        ended = "completed_at" if terminal == "completed" else "failed_at"
        minimal = {"incident_id": incident_id, "org_id": "tenant-legacy", "status": terminal,
                   ended: "2020-01-01T00:00:00+00:00"}
        store = IncidentStore(storage)
        for pass_number in (1, 2):
            store.apply_retention("tenant-legacy")
            claim = storage.get_json(claim_key)
            print(f"LEGACY terminal={terminal} pass={pass_number} claim_status={claim.get('status')} "
                  f"claim_has_context={'context' in claim} legacy_exists={storage.exists(legacy_key)}")
            assert "context" not in claim
            assert claim == minimal
            if terminal == "completed":
                assert storage.get_json(legacy_key) == minimal
            else:
                assert not storage.exists(legacy_key)

    @pytest.mark.parametrize("terminal", ["completed", "failed"])
    def test_legacy_claim_compaction_failure_preserves_terminal_source(self, monkeypatch, review_context, terminal):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-legacy", review_context, terminal)
        claim_key = storage.review_claim_key("tenant-legacy", entry["incident_id"])
        put = storage.put_json
        failure = None

        def fail_claim_compaction(key, data):
            if key == claim_key and "context" not in data:
                raise RuntimeError("legacy claim unavailable")
            return put(key, data)

        with monkeypatch.context() as injection:
            injection.setattr(storage, "put_json", fail_claim_compaction)
            try:
                IncidentStore(storage).apply_retention("tenant-legacy")
            except RuntimeError as error:
                failure = error
        assert storage.get_json(legacy_key) == entry
        assert failure is not None
        assert storage.get_json(claim_key)["context"] == review_context
        for _ in range(2):
            IncidentStore(storage).apply_retention("tenant-legacy")
            claim = storage.get_json(claim_key)
            assert "context" not in claim and claim["status"] == terminal

    def test_completed_legacy_head_dedupes_after_retention(self, monkeypatch, review_context):
        monkeypatch.setenv("AUDIT_RETENTION_DAYS", "1")
        storage = MemoryStorage()
        entry, legacy_key = _seed_legacy_review(storage, "tenant-adopt", review_context, "completed")
        entry["completed_at"] = "2020-01-01T00:00:00+00:00"
        storage.put_json(legacy_key, entry)
        queue = IncidentQueue(storage)
        assert queue.adopt_legacy_reviews() == 0
        assert storage.get_json(legacy_key) == entry
        assert queue.enqueue("tenant-adopt", review_context) == entry["incident_id"]
        IncidentStore(storage).apply_retention("tenant-adopt")
        assert queue.enqueue("tenant-adopt", review_context) == entry["incident_id"]
        assert queue.claim_next("tenant-adopt") is None
        assert "context" not in storage.get_json(legacy_key)
        assert storage.list_keys("tenant-adopt/review_heads/") == []

    def test_head_lookup_does_not_read_other_review_history(self, review_context):
        storage = RecordingStorage()
        queue = IncidentQueue(storage)
        incident_id = queue.enqueue("tenant", review_context)
        expected_prefix = storage.org_prefix("tenant", "review_heads") + "/"
        owned_slot = _review_marker_key(storage, "tenant", incident_id)
        entry = storage.get_json(owned_slot)
        head_prefix = entry["review_slot"].rsplit("/", 1)[0] + "/"
        counts = []
        for size in (100, 1000):
            for index in range(size):
                storage.put_json(expected_prefix + f"other-{index}/00000000000000000000.json",
                                 {"incident_id": f"other-{index}"})
            storage.reads.clear()
            storage.listings.clear()
            assert queue.enqueue("tenant", review_context) == incident_id
            counts.append(len(storage.reads))
            assert storage.listings == [head_prefix]
            assert all("other-" not in key for key in storage.reads)
        assert counts[0] == counts[1]

    @pytest.mark.asyncio
    async def test_failed_adoption_releases_startup_lock(self, monkeypatch, tmp_path):
        import api.server as server
        from services.background_lock import acquire_background_worker_lock, release_background_worker_lock

        queue = IncidentQueue(MemoryStorage())
        assert callable(getattr(queue, "adopt_legacy_reviews", None))
        def fail_adoption():
            raise RuntimeError("adoption unavailable")
        monkeypatch.setattr(queue, "adopt_legacy_reviews", fail_adoption)
        monkeypatch.setattr(server, "incident_queue", queue)
        monkeypatch.setenv("BACKGROUND_WORKER_LOCK", str(tmp_path / "worker.lock"))
        with pytest.raises(RuntimeError, match="adoption unavailable"):
            async with server.lifespan(server.app):
                pass
        lock = acquire_background_worker_lock()
        try:
            assert lock is not None
        finally:
            release_background_worker_lock(lock)


def _seed_legacy_review(storage, org_id, context, state):
    # Run the unmodified base queue so fixtures retain every lifecycle artifact.
    queue_class = runpy.run_path(str(Path(__file__).parent / "fixtures" / "incident_queue_c3bbc901.py"))["IncidentQueue"]
    queue = queue_class(storage)
    incident_id = queue.enqueue(org_id, context)
    if state != "pending":
        assert queue.claim_next(org_id)["incident_id"] == incident_id
    if state == "completed":
        queue.mark_completed(org_id, incident_id, {})
    elif state == "failed":
        queue.mark_failed(org_id, incident_id, "unavailable")
    legacy_key = storage.queue_key(org_id, "reviews", incident_id)
    for key in (legacy_key, storage.review_claim_key(org_id, incident_id)):
        entry = storage.get_json(key)
        if entry:
            for field in ("created_at", "claimed_at", "completed_at", "failed_at"):
                if field in entry:
                    entry[field] = "2020-01-01T00:00:00+00:00"
            storage.put_json(key, entry)
    return storage.get_json(legacy_key), legacy_key
