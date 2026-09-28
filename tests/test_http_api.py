"""HTTP API 端到端：真实启动服务，经 HTTP 走完整流程与鉴权。"""
import base64
import json
import unittest
import urllib.error
import urllib.request

from service_09252_006.api.http_api import HttpApiServer
from service_09252_006.application.container import ApplicationContext
from tests.support import Harness


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None,
                 bootstrap: str | None = None) -> None:
        self.base_url = base_url
        self.token = token
        self.bootstrap = bootstrap

    def request(self, method: str, path: str, body=None,
                idempotency_key=None, raw=False):
        url = self.base_url + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.bootstrap:
            headers["X-Bootstrap-Token"] = self.bootstrap
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload, dict(resp.headers)
                return resp.status, json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if raw:
                return exc.code, payload, dict(exc.headers)
            try:
                return exc.code, json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                return exc.code, {"raw": payload.decode("utf-8")}


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot-secret"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot-secret")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def _create_user(self, user_id, roles, institution_id=None, token=None):
        status, body = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": user_id, "roles": roles,
             "institution_id": institution_id},
        )
        self.assertEqual(status, 201, body)
        if token:
            status, body = self.boot.request(
                "POST", "/v1/admin/tokens",
                {"user_id": user_id, "token": token},
            )
            self.assertEqual(status, 201, body)
        return ApiClient(self.base, token=token)

    def test_end_to_end_over_http_with_minimal_disclosure(self) -> None:
        admin = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-admin"
        )
        submitter = self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )
        authority = self._create_user(
            "auth", ["quality_authority"], None, "tok-auth"
        )
        reviewer = self._create_user(
            "rev-1", ["reviewer"], "inst-ext", "tok-rev"
        )

        # 未认证被拒
        status, body = ApiClient(self.base).request("GET", "/v1/packages")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "permission_denied")

        # 引导端点需要 bootstrap token
        status, body = ApiClient(self.base).request(
            "POST", "/v1/admin/users",
            {"user_id": "x", "roles": [], "institution_id": None},
        )
        self.assertEqual(status, 403)

        # 接收证据
        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "enterprise_feedback", "title": "企业反馈",
             "sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201)
        content = "敏感：企业 X 要求不具名".encode("utf-8")
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii"),
             "media_type": "text/plain"},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        # 幂等重放
        status, ver2 = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii")},
            idempotency_key="upload-1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(ver["version_id"], ver2["version_id"])
        self.assertTrue(ver2["replayed"])

        # 组包封存
        status, pkg = admin.request("POST", "/v1/packages", {"title": "2026秋"})
        pid = pkg["package_id"]
        status, _ = admin.request(
            "POST", f"/v1/packages/{pid}/entries",
            {"version_id": ver["version_id"]},
        )
        self.assertEqual(status, 201)
        status, sealed = admin.request("POST", f"/v1/packages/{pid}/seal", {})
        self.assertEqual(status, 200)
        self.assertIn("manifest_fingerprint", sealed)

        # 提交人看不到敏感反馈内容
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(status, 200)
        self.assertTrue(view["entries"][0]["redacted"])
        status, resp = submitter.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
        )
        self.assertEqual(status, 403)

        # 分配评审后可见可下载
        status, req = authority.request(
            "POST", f"/v1/packages/{pid}/assignments",
            {"reviewer_id": "rev-1",
             "deadline_local_iso": "2026-09-25T18:00",
             "deadline_timezone": "Asia/Shanghai"},
        )
        self.assertEqual(status, 201)
        rid = req["request_id"]
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/respond", {"accept": True}
        )
        self.assertEqual(status, 200)
        status, payload, headers = reviewer.request(
            "GET", f"/v1/packages/{pid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, content)
        self.assertEqual(headers["X-Content-Sha256"], ver["sha256"])

        # 评审通过并签发
        status, _ = reviewer.request(
            "POST", f"/v1/requests/{rid}/verdict",
            {"verdict": "approve", "comment": "材料齐备"},
        )
        self.assertEqual(status, 200)
        status, decision = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "approved", "note": "通过"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        status, decision2 = authority.request(
            "POST", f"/v1/packages/{pid}/decision",
            {"decision": "rejected", "note": "重复请求应回放"},
            idempotency_key="decide-1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision2["decision"], "approved")
        self.assertTrue(decision2["replayed"])

    def test_redaction_versions_over_http(self) -> None:
        admin = self._create_user(
            "admin-a", ["institution_admin"], "inst-a", "tok-admin"
        )
        submitter = self._create_user(
            "sub-a", ["institution_submitter"], "inst-a", "tok-sub"
        )
        other = self._create_user(
            "admin-b", ["institution_admin"], "inst-b", "tok-b"
        )

        original = "敏感：企业 X 联系人张三 13800000000".encode("utf-8")
        cut_v1 = "敏感：某企业提出建议（已匿名 v1）".encode("utf-8")
        cut_v2 = "敏感：企业反馈已脱敏 v2".encode("utf-8")

        status, mat = admin.request(
            "POST", "/v1/materials",
            {"kind": "enterprise_feedback", "title": "企业反馈",
             "sensitivity": "sensitive"},
        )
        self.assertEqual(status, 201)
        status, ver = admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(original).decode("ascii")},
        )
        self.assertEqual(status, 201)
        vid = ver["version_id"]

        status, pkg = admin.request("POST", "/v1/packages", {"title": "包"})
        pid = pkg["package_id"]
        admin.request("POST", f"/v1/packages/{pid}/entries", {"version_id": vid})
        admin.request("POST", f"/v1/packages/{pid}/seal", {})

        # 普通成员：封存时无脱敏版本 -> hidden，下载 403
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(view["entries"][0]["content_tier"], "hidden")
        status, _ = submitter.request(
            "GET", f"/v1/packages/{pid}/entries/{vid}/content"
        )
        self.assertEqual(status, 403)

        # 外机构管理员不能制作脱敏版本
        status, body = other.request(
            "POST", f"/v1/versions/{vid}/redactions",
            {"content_base64": base64.b64encode(cut_v1).decode("ascii")},
        )
        self.assertEqual(status, 403)

        # v1（不自动启用），普通成员仍 hidden
        status, r1 = admin.request(
            "POST", f"/v1/versions/{vid}/redactions",
            {"content_base64": base64.b64encode(cut_v1).decode("ascii"),
             "note": "首版裁剪"},
            idempotency_key="rdc-v1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(r1["redaction_no"], 1)
        self.assertIsNone(r1["activated_at"])
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(view["entries"][0]["content_tier"], "hidden")

        # 启用 v1；历史包封存时无脱敏版本，显示不变（仍 hidden）
        status, _ = admin.request(
            "POST", f"/v1/redactions/{r1['redaction_id']}/activate", {}
        )
        self.assertEqual(status, 200)
        status, view = submitter.request("GET", f"/v1/packages/{pid}")
        self.assertEqual(view["entries"][0]["content_tier"], "hidden")

        # 新封存的复审包固定 v1：普通成员拿到裁剪文
        status, pkg2 = admin.request(
            "POST", "/v1/packages",
            {"title": "新包", "supersedes_package_id": None},
        )
        # 不用复审链（旧包未决定），直接建普通包
        pid2 = pkg2["package_id"]
        admin.request("POST", f"/v1/packages/{pid2}/entries", {"version_id": vid})
        admin.request("POST", f"/v1/packages/{pid2}/seal", {})
        status, view = submitter.request("GET", f"/v1/packages/{pid2}")
        entry = view["entries"][0]
        self.assertEqual(entry["content_tier"], "redacted")
        self.assertEqual(entry["redaction_id"], r1["redaction_id"])
        status, payload, headers = submitter.request(
            "GET", f"/v1/packages/{pid2}/entries/{vid}/content", raw=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, cut_v1)
        self.assertEqual(headers["X-Content-Tier"], "redacted")

        # 直接下载脱敏版本：本机构成员可，外机构 403
        status, payload, _ = submitter.request(
            "GET", f"/v1/redactions/{r1['redaction_id']}/content", raw=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, cut_v1)
        status, _ = other.request(
            "GET", f"/v1/redactions/{r1['redaction_id']}/content"
        )
        self.assertEqual(status, 403)

        # 再脱敏 v2 并启用：旧包(pid2)仍固定 v1，新包固定 v2
        status, r2 = admin.request(
            "POST", f"/v1/versions/{vid}/redactions",
            {"content_base64": base64.b64encode(cut_v2).decode("ascii"),
             "activate": True},
        )
        self.assertEqual(status, 201)
        status, view = submitter.request("GET", f"/v1/packages/{pid2}")
        self.assertEqual(view["entries"][0]["redaction_id"], r1["redaction_id"])
        status, payload, _ = submitter.request(
            "GET", f"/v1/packages/{pid2}/entries/{vid}/content", raw=True
        )
        self.assertEqual(payload, cut_v1)  # 切换后旧反馈仍可读且不变

        status, pkg3 = admin.request("POST", "/v1/packages", {"title": "包3"})
        pid3 = pkg3["package_id"]
        admin.request("POST", f"/v1/packages/{pid3}/entries", {"version_id": vid})
        admin.request("POST", f"/v1/packages/{pid3}/seal", {})
        status, view = submitter.request("GET", f"/v1/packages/{pid3}")
        self.assertEqual(view["entries"][0]["redaction_id"], r2["redaction_id"])

        # 版本列表与幂等回放
        status, listed = admin.request(
            "GET", f"/v1/versions/{vid}/redactions"
        )
        self.assertEqual([r["redaction_no"] for r in listed["redactions"]], [1, 2])
        status, replay = admin.request(
            "POST", f"/v1/versions/{vid}/redactions",
            {"content_base64": base64.b64encode(cut_v1).decode("ascii")},
            idempotency_key="rdc-v1",
        )
        self.assertEqual(replay["redaction_id"], r1["redaction_id"])
        self.assertTrue(replay["replayed"])

    def test_health(self) -> None:
        status, body = ApiClient(self.base).request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])


if __name__ == "__main__":
    unittest.main()
