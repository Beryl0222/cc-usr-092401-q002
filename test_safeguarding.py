"""网络侵害事件受理与协同处置的全链路契约测试。"""

import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app import AppError, SafeguardingApp, content_hash, suggest_severity
from service import build_handler

AGENT = {"name": "代理人小林", "role": "当事人代理"}
OFFICER = {"name": "保护专员阿岚", "role": "俱乐部保护专员"}
DUTY = {"name": "值班主管老周", "role": "俱乐部值班主管"}
LIASON = {"name": "平台联络员小孟", "role": "平台联络员"}
LEGAL = {"name": "法务复核员老许", "role": "法务复核员"}

THREAT_TEXT = "你在19号更衣室门口等着，今晚别想走着出去"
CRITICISM_TEXT = "这场换人太晚，球员状态明显不行，踢得太差"


def threat_report(**overrides):
    payload = {
        "victim_code": "ATH-007",
        "platform": "weibo",
        "content_url": "https://weibo.example/comment/90210",
        "raw_excerpt": THREAT_TEXT,
        "severity": "direct_threat",
        "linked_accounts": [
            {"platform": "weibo", "account_key": "u_threat_77",
             "url": "https://weibo.example/u/77", "display_name": "黑哨敢死队"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint",
                  "police_report", "public_statement"],
    }
    payload.update(overrides)
    return payload


def abuse_report(**overrides):
    payload = {
        "victim_code": "ATH-009",
        "platform": "douyin",
        "content_url": "https://video.example/comment/55",
        "raw_excerpt": "这人就该被网暴到退役，全家都不是好东西",
        "severity": "abuse",
        "linked_accounts": [
            {"platform": "douyin", "account_key": "dy_hater_9",
             "url": "https://video.example/u/9", "display_name": "辱骂账号"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint"],
    }
    payload.update(overrides)
    return payload


class DomainRulesTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()

    def test_severity_suggestion_is_advisory(self):
        self.assertEqual(suggest_severity(THREAT_TEXT), "direct_threat")
        self.assertEqual(suggest_severity(CRITICISM_TEXT), "criticism")

    def test_criticism_is_logged_but_not_opened_as_incident(self):
        result = self.app.submit_report(
            {"victim_code": "ATH-001", "platform": "weibo",
             "content_url": "https://weibo.example/comment/1",
             "raw_excerpt": CRITICISM_TEXT, "severity": "criticism"}, AGENT)
        self.assertIsNone(result["incident_id"])
        self.assertIn("不立案", result["decision"])
        self.assertEqual(self.app.list_incidents(), [])
        # 线索仍可查，便于观察是否升级为网暴
        self.assertEqual(len(self.app.list_reports()), 1)

    def test_unknown_severity_and_missing_reference_rejected(self):
        with self.assertRaises(AppError):
            self.app.submit_report(
                {"victim_code": "ATH-001", "content_url": "u", "severity": "bomb"}, AGENT)
        with self.assertRaises(AppError):
            self.app.submit_report(
                {"victim_code": "ATH-001", "severity": "abuse"}, AGENT)

    def test_raw_content_never_enters_the_ledger(self):
        result = self.app.submit_report(threat_report(), AGENT)
        dumped = json.dumps(self.app.store.replay(), ensure_ascii=False)
        self.assertNotIn(THREAT_TEXT, dumped)  # 原始内容不入库
        digest = self.app.incident_digest(result["incident_id"])
        self.assertEqual(digest["证据依据"]["evidence"][0]["content_sha256"],
                         content_hash(THREAT_TEXT))
        self.assertEqual(digest["证据依据"]["evidence"][0]["content_ref"],
                         "https://weibo.example/comment/90210")


class DutyEscalationTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.result = self.app.submit_report(threat_report(), AGENT)
        self.incident_id = self.result["incident_id"]

    def test_direct_threat_escalates_once_with_dedup_notifications(self):
        digest = self.app.incident_digest(self.incident_id)
        self.assertTrue(digest["尚未完成的保护动作"]["open_escalation"])
        notifs = self.app.list_notifications(self.incident_id)
        roles = sorted(n["to_role"] for n in notifs)
        self.assertEqual(roles, ["俱乐部保护专员", "俱乐部值班主管"])

        # 再次以直接威胁确认：只刷新确认时间，不产生第二案件、不第二次通知
        self.app.confirm_severity(self.incident_id, "direct_threat", OFFICER)
        self.assertEqual(len(self.app.incidents), 1)
        self.assertEqual(len(self.app.list_notifications(self.incident_id)), 2)
        digest = self.app.incident_digest(self.incident_id)
        self.assertIsNotNone(digest["值班升级"]["last_confirmed_at"])

        # 值班主管响应后升级关闭
        self.app.acknowledge_escalation(self.incident_id, DUTY)
        self.assertFalse(
            self.app.incident_digest(self.incident_id)["尚未完成的保护动作"]["open_escalation"])

    def test_only_duty_lead_can_acknowledge(self):
        with self.assertRaises(AppError):
            self.app.acknowledge_escalation(self.incident_id, OFFICER)


class CallbackIdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.callback = {
            "callback_id": "CB-001",
            "incident_id": self.incident_id,
            "receipt": {
                "receipt_id": "DY-8840217", "platform": "douyin",
                "status": "removed",
                "reported_at": "2026-09-18T21:03:00+08:00",
                "content_url": "https://video.example/comment/55",
            },
            "account": {"platform": "douyin", "account_key": "dy_hater_9",
                        "display_name": "改名前的账号名"},
        }

    def test_repeated_callback_attaches_once_notifies_nothing(self):
        first = self.app.platform_callback(self.callback)
        self.assertFalse(first["duplicate"])
        self.assertIn("content_deleted", first["attached"])

        second = self.app.platform_callback(self.callback)
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["incident_id"], self.incident_id)
        self.assertEqual(len(self.app.incidents), 1)  # 没有第二案件
        self.assertEqual(self.app.list_notifications(), [])  # 回调不通知

        digest = self.app.incident_digest(self.incident_id)
        states = [e["state"] for e in digest["证据依据"]["evidence"]]
        self.assertIn("deleted", states)
        receipts = digest["证据依据"]["platform_receipts"]
        self.assertEqual(len(receipts), 1)

    def test_rename_callback_appends_history_without_breaking_chain(self):
        self.app.platform_callback(self.callback)
        renamed = dict(self.callback)
        renamed["account"] = {"platform": "douyin", "account_key": "dy_hater_9",
                              "display_name": "改名后的账号名"}
        response = self.app.platform_callback(renamed)
        self.assertTrue(response["duplicate"])  # 同 callback_id：不重复处理改名
        new_cb = json.loads(json.dumps(self.callback))
        new_cb["callback_id"] = "CB-002"
        new_cb["account"]["display_name"] = "改名后的账号名"
        response = self.app.platform_callback(new_cb)
        self.assertFalse(response["duplicate"])
        digest = self.app.incident_digest(self.incident_id)
        account = digest["证据依据"]["linked_accounts"][0]
        self.assertTrue(account["renamed"])
        self.assertEqual(account["display_name"], "改名后的账号名")
        self.assertEqual([h["name"] for h in account["name_history"]],
                         ["辱骂账号", "改名前的账号名", "改名后的账号名"])

    def test_callback_unknown_reference_cannot_open_case(self):
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback({
                "callback_id": "CB-404",
                "receipt": {"receipt_id": "NOPE", "content_url": "https://x/unknown"}})
        self.assertEqual(ctx.exception.status, 404)


class ActionSeparationAndConsentTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]

    def test_reviewer_role_and_self_review_are_enforced(self):
        action_id = self.app.propose_action(
            self.incident_id, "platform_complaint", AGENT)["action_id"]
        with self.assertRaises(AppError) as ctx:
            self.app.review_action(action_id, "approve", AGENT)
        self.assertEqual(ctx.exception.status, 403)  # 禁止自复核
        with self.assertRaises(AppError) as ctx:
            self.app.review_action(action_id, "approve", LEGAL)
        self.assertEqual(ctx.exception.status, 403)  # 法务不能复核平台投诉
        reviewed = self.app.review_action(action_id, "approve", LIASON)
        self.assertEqual(reviewed["status"], "approved")
        executed = self.app.execute_action(action_id, LIASON)
        self.assertEqual(executed["status"], "executed")
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)

    def test_rejection_needs_resubmission_and_no_double_review(self):
        action_id = self.app.propose_action(
            self.incident_id, "public_statement", AGENT)["action_id"]
        self.app.review_action(action_id, "reject", LEGAL, reason="事实未清，不宜公开")
        with self.assertRaises(AppError):
            self.app.review_action(action_id, "approve", LEGAL)

    def test_revoked_consent_blocks_pending_action_but_keeps_chain(self):
        first = self.app.propose_action(
            self.incident_id, "platform_complaint", AGENT)["action_id"]
        self.app.review_action(first, "approve", LIASON)
        self.app.execute_action(first, LIASON)  # 已执行的投诉不可逆转

        second = self.app.propose_action(
            self.incident_id, "platform_complaint", AGENT)["action_id"]
        self.app.review_action(second, "approve", LIASON)
        self.app.revoke_consent(self.incident_id, ["platform_complaint"], AGENT)

        with self.assertRaises(AppError) as ctx:
            self.app.execute_action(second, LIASON)
        self.assertEqual(ctx.exception.status, 409)
        digest = self.app.incident_digest(self.incident_id)
        blocked = next(a for a in digest["处置决定"] if a["action_id"] == second)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("授权已撤回", blocked["blocked_reason"])
        # 已执行动作与授权撤回事件都留在责任链
        chain_types = [c["type"] for c in digest["责任链"]]
        self.assertIn("action_executed", chain_types)
        self.assertIn("consent_revoked", chain_types)

        # 重新授权后可执行，不产生新事件以外的重复案件
        self.app.grant_consent(self.incident_id, ["platform_complaint"], AGENT)
        self.assertEqual(self.app.execute_action(second, LIASON)["status"], "executed")
        self.assertEqual(len(self.app.incidents), 1)


class ClusteringAndMergingTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        same = threat_report()
        self.first_id = self.app.submit_report(same, AGENT)["incident_id"]
        self.app.acknowledge_escalation(self.first_id, DUTY)
        # 先响应升级，避免第二事件也升级影响后续关闭类断言
        second = threat_report(content_url="https://weibo.example/comment/90210?mirror=1",
                               receipts=[{"receipt_id": "WB-2026-09-18-7781",
                                          "platform": "weibo", "status": "accepted"}])
        self.second_id = self.app.submit_report(second, AGENT)["incident_id"]
        self.app.acknowledge_escalation(self.second_id, DUTY)

    def test_cluster_is_only_a_suggestion_until_officer_confirms(self):
        suggestions = self.app.list_suggestions()
        self.assertEqual(len(suggestions), 1)
        sugg = suggestions[0]
        self.assertEqual(sugg["status"], "open")
        self.assertIn("内容哈希", sugg["reason"])
        # 自动聚类没有擅自合并
        self.assertIsNone(self.app.incidents[self.first_id]["merged_into"])

    def test_reject_suggestion_keeps_two_cases(self):
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]
        self.app.resolve_suggestion(sugg_id, "reject", OFFICER)
        self.assertIsNone(self.app.incidents[self.first_id]["merged_into"])

    def test_accept_suggestion_merges_and_preserves_full_chain(self):
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]
        result = self.app.resolve_suggestion(sugg_id, "accept", OFFICER,
                                             target_incident=self.first_id)
        self.assertEqual(result["merged_into"], self.first_id)
        survivor = self.app.incident_digest(self.first_id)
        self.assertEqual(survivor["absorbed_incidents"], [self.second_id])
        chain_reports = {c["payload"].get("report_no") for c in survivor["责任链"]
                         if c["type"] == "report_received"}
        self.assertEqual(len(chain_reports), 2)  # 两条线索的责任链都在
        with self.assertRaises(AppError) as ctx:
            self.app.add_evidence(self.second_id, {"content_ref": "u"}, AGENT)
        self.assertEqual(ctx.exception.status, 409)  # 被合并事件不可再操作


class AppealTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]

    def test_appeal_masks_sensitive_material_and_blocks_external_action(self):
        self.app.open_appeal(self.incident_id, "当事人称账号被盗，内容系误认", AGENT)
        digest_agent = self.app.incident_digest(self.incident_id, as_role="当事人代理")
        self.assertEqual(digest_agent["status"], "申诉中")
        self.assertIn("限制", digest_agent["证据依据"]["evidence"][0]["content_ref"])
        self.assertIn("限制", digest_agent["证据依据"]["linked_accounts"][0]["account_key"])

        digest_legal = self.app.incident_digest(self.incident_id, as_role="法务复核员")
        self.assertEqual(digest_legal["证据依据"]["evidence"][0]["content_ref"],
                         "https://video.example/comment/55")

        with self.assertRaises(AppError):
            self.app.propose_action(self.incident_id, "public_statement", AGENT)
        with self.assertRaises(AppError):
            self.app.add_evidence(self.incident_id, {"content_ref": "https://new"}, AGENT)
        # 申诉期间证据留存授权不可撤回
        with self.assertRaises(AppError):
            self.app.revoke_consent(self.incident_id, ["evidence_storage"], AGENT)

    def test_upheld_appeal_closes_case_but_chain_remains(self):
        self.app.open_appeal(self.incident_id, "误认", AGENT)
        self.app.resolve_appeal(self.incident_id, "upheld", LEGAL, note="证据不足，误报成立")
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(digest["status"], "已关闭")
        self.assertIn("误报", digest["close_reason"])
        self.assertTrue(any(c["type"] == "evidence_registered" for c in digest["责任链"]))

    def test_dismissed_appeal_resumes_protection(self):
        self.app.open_appeal(self.incident_id, "误认", AGENT)
        self.app.resolve_appeal(self.incident_id, "dismissed", LEGAL)
        digest = self.app.incident_digest(self.incident_id, as_role="当事人代理")
        self.assertNotEqual(digest["status"], "申诉中")
        self.assertEqual(digest["证据依据"]["evidence"][0]["content_ref"],
                         "https://video.example/comment/55")


class ClosureAndDigestTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()

    def test_cannot_close_with_open_escalation_or_pending_actions(self):
        incident_id = self.app.submit_report(threat_report(), AGENT)["incident_id"]
        with self.assertRaises(AppError):
            self.app.close_incident(incident_id, "想关掉", OFFICER)
        self.app.acknowledge_escalation(incident_id, DUTY)
        action_id = self.app.propose_action(incident_id, "protection_plan", AGENT)["action_id"]
        with self.assertRaises(AppError):
            self.app.close_incident(incident_id, "还有待办", OFFICER)
        # 保护方案由保护专员复核（提交人与复核人不得为同一人）
        self.app.review_action(action_id, "approve", OFFICER)
        self.app.execute_action(action_id, OFFICER)
        self.app.close_incident(incident_id, "保护到位", OFFICER)
        self.assertEqual(self.app.incident_digest(incident_id)["status"], "已关闭")

    def test_digest_shows_four_pillars(self):
        incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        digest = self.app.incident_digest(incident_id)
        for key in ("证据依据", "处置决定", "当事人当前授权范围", "尚未完成的保护动作"):
            self.assertIn(key, digest)
        scopes = {s["code"] for s in digest["当事人当前授权范围"]}
        self.assertEqual(scopes, {"report", "evidence_storage", "platform_complaint"})


class PersistenceTest(unittest.TestCase):
    def test_ledger_replay_restores_state_and_callback_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app = SafeguardingApp(store_path=path)
            incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
            app.platform_callback({
                "callback_id": "CB-PERSIST", "incident_id": incident_id,
                "receipt": {"receipt_id": "R1", "platform": "douyin", "status": "processing"}})

            reloaded = SafeguardingApp(store_path=path)
            self.assertIn(incident_id, reloaded.incidents)
            again = reloaded.platform_callback({
                "callback_id": "CB-PERSIST", "incident_id": incident_id,
                "receipt": {"receipt_id": "R1", "platform": "douyin", "status": "removed"}})
            self.assertTrue(again["duplicate"])  # 重放后重复回调仍不二次处理
            self.assertEqual(len(reloaded.list_notifications()), 0)


class AppealActionRaceTest(unittest.TestCase):
    """申诉与对外动作之间的竞态：冻结、恢复、取消、并发唯一顺序。"""

    def setUp(self):
        self.app = SafeguardingApp()

    def _approved_complaint(self, report=None):
        incident_id = self.app.submit_report(report or abuse_report(), AGENT)["incident_id"]
        action_id = self.app.propose_action(
            incident_id, "platform_complaint", AGENT)["action_id"]
        self.app.review_action(action_id, "approve", LIASON, reason="侵权事实清楚，准予投诉")
        return incident_id, action_id

    def _action(self, action_id):
        return self.app.actions[action_id]

    def _events_for(self, action_id, *types):
        return [e for e in self.app.store.replay()
                if e["type"] in types and e["payload"].get("action_id") == action_id]

    # ---------------------------------------------------------- 冻结与依据
    def test_open_appeal_freezes_approved_action_but_keeps_approval_basis(self):
        incident_id, action_id = self._approved_complaint()
        result = self.app.open_appeal(incident_id, "当事人称账号被盗", AGENT)
        self.assertEqual(result["frozen_actions"], [action_id])

        action = self._action(action_id)
        self.assertEqual(action["status"], "frozen")  # 不再以 approved 示人
        self.assertEqual(action["frozen_from_status"], "approved")
        # 原审批/复核依据完整保留
        self.assertEqual(action["reviewer"], LIASON["name"])
        self.assertEqual(action["review_reason"], "侵权事实清楚，准予投诉")

        digest = self.app.incident_digest(incident_id)
        view = next(a for a in digest["处置决定"] if a["action_id"] == action_id)
        self.assertEqual(view["status"], "frozen")
        self.assertEqual(view["frozen"]["from_status"], "approved")
        self.assertEqual(view["frozen"]["reviewer"], LIASON["name"])
        self.assertNotIn(action_id, digest["尚未完成的保护动作"]["action_ids"])
        self.assertIn(action_id, digest["尚未完成的保护动作"]["frozen_action_ids"])

        # 冻结期间手工执行被拒绝（409），不产生外发
        with self.assertRaises(AppError) as ctx:
            self.app.execute_action(action_id, LIASON)
        self.assertEqual(ctx.exception.status, 409)
        self.assertIsNone(self._action(action_id)["executed_at"])

    def test_executed_action_is_fact_and_never_rolled_back_by_upheld(self):
        incident_id, first = self._approved_complaint()
        self.app.execute_action(first, LIASON)  # 已外发，既成事实
        second = self.app.propose_action(
            incident_id, "public_statement", AGENT)["action_id"]
        self.app.review_action(second, "approve", LEGAL)

        self.app.open_appeal(incident_id, "误认", AGENT)
        self.assertEqual(self._action(first)["status"], "executed")  # 已执行不冻结
        self.assertEqual(self._action(second)["status"], "frozen")
        self.app.resolve_appeal(incident_id, "upheld", LEGAL)

        self.assertEqual(self._action(first)["status"], "executed")  # 不回滚
        self.assertIsNotNone(self._action(first)["executed_at"])
        self.assertEqual(self._action(second)["status"], "cancelled")  # 待执行被取消
        digest = self.app.incident_digest(incident_id)
        self.assertEqual(digest["status"], "已关闭")
        # 已完成动作的平台回执作为事实仍在
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)
        self.assertNotIn(first, digest["尚未完成的保护动作"]["cancelled_action_ids"])
        self.assertIn(second, digest["尚未完成的保护动作"]["cancelled_action_ids"])

    # ---------------------------------------------------------- 两种裁定
    def test_dismissed_appeal_reinstates_action_and_it_executes(self):
        incident_id, action_id = self._approved_complaint()
        self.app.open_appeal(incident_id, "误认", AGENT)
        self.assertEqual(self._action(action_id)["status"], "frozen")
        self.app.resolve_appeal(incident_id, "dismissed", LEGAL)
        self.assertEqual(self._action(action_id)["status"], "approved")  # 恢复冻结前状态
        self.assertEqual(self.app.execute_action(action_id, LIASON)["status"], "executed")

    def test_dismissed_with_revoked_consent_keeps_frozen_until_regrant(self):
        incident_id, action_id = self._approved_complaint()
        self.app.open_appeal(incident_id, "误认", AGENT)
        # 冻结期间当事人撤回平台投诉授权（非证据留存，允许）
        self.app.revoke_consent(incident_id, ["platform_complaint"], AGENT)
        self.app.resolve_appeal(incident_id, "dismissed", LEGAL)

        # 申诉驳回但授权缺失：只记录未恢复，动作仍冻结、不可执行
        self.assertEqual(self._action(action_id)["status"], "frozen")
        with self.assertRaises(AppError) as ctx:
            self.app.execute_action(action_id, LIASON)
        self.assertEqual(ctx.exception.status, 409)

        # 重新授权齐备后自动恢复原已批准状态，再执行
        self.app.grant_consent(incident_id, ["platform_complaint"], AGENT)
        self.assertEqual(self._action(action_id)["status"], "approved")
        self.assertEqual(self.app.execute_action(action_id, LIASON)["status"], "executed")

    def test_dismissed_reinstates_pending_action_for_review(self):
        incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        action_id = self.app.propose_action(
            incident_id, "platform_complaint", AGENT)["action_id"]
        self.app.open_appeal(incident_id, "误认", AGENT)
        self.assertEqual(self._action(action_id)["frozen_from_status"], "pending")
        self.app.resolve_appeal(incident_id, "dismissed", LEGAL)
        self.assertEqual(self._action(action_id)["status"], "pending")
        self.assertEqual(
            self.app.review_action(action_id, "approve", LIASON)["status"], "approved")

    def test_upheld_cancels_pending_internal_action_too(self):
        incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        plan = self.app.propose_action(
            incident_id, "protection_plan", AGENT)["action_id"]
        self.app.open_appeal(incident_id, "误认", AGENT)
        # 内部动作不参与对外冻结，但申诉成立时一并取消待执行项
        self.assertEqual(self._action(plan)["status"], "pending")
        self.app.resolve_appeal(incident_id, "upheld", LEGAL)
        self.assertEqual(self._action(plan)["status"], "cancelled")

    # ---------------------------------------------------------- 旁路防护
    def test_consent_revoke_cannot_unfreeze_during_appeal(self):
        incident_id, action_id = self._approved_complaint()
        self.app.open_appeal(incident_id, "误认", AGENT)
        self.app.revoke_consent(incident_id, ["platform_complaint"], AGENT)
        self.app.grant_consent(incident_id, ["platform_complaint"], AGENT)
        # 申诉仍存续：授权变动绝不解冻
        self.assertEqual(self._action(action_id)["status"], "frozen")
        with self.assertRaises(AppError):
            self.app.execute_action(action_id, LIASON)

    def test_merge_blocked_while_appeal_or_frozen(self):
        first = threat_report()
        first_id = self.app.submit_report(first, AGENT)["incident_id"]
        self.app.acknowledge_escalation(first_id, DUTY)
        second = threat_report(content_url="https://weibo.example/comment/90210?mirror=2")
        second_id = self.app.submit_report(second, AGENT)["incident_id"]
        self.app.acknowledge_escalation(second_id, DUTY)
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]

        self.app.open_appeal(first_id, "误认", AGENT)
        with self.assertRaises(AppError) as ctx:
            self.app.resolve_suggestion(sugg_id, "accept", OFFICER,
                                        target_incident=first_id)
        self.assertEqual(ctx.exception.status, 409)  # 申诉存续不得合并
        self.assertIsNone(self.app.incidents[second_id]["merged_into"])
        # 申诉驳回且无冻结后，合并恢复可用
        self.app.resolve_appeal(first_id, "dismissed", LEGAL)
        result = self.app.resolve_suggestion(sugg_id, "accept", OFFICER,
                                             target_incident=first_id)
        self.assertEqual(result["merged_into"], first_id)

    # ---------------------------------------------------------- 并发唯一顺序
    def test_execute_committed_first_is_honoured_and_not_cancelled(self):
        # 确定性"执行先手"：执行事务先在账本落 seq，申诉随后打开。
        # 已执行动作是既成事实，申诉不得冻结/取消它，回执事实保留。
        incident_id, action_id = self._approved_complaint()
        self.assertEqual(self.app.execute_action(action_id, LIASON)["status"], "executed")
        self.app.open_appeal(incident_id, "事后才申诉", AGENT)
        self.assertEqual(self._action(action_id)["status"], "executed")
        self.assertEqual(
            self._events_for(action_id, "action_frozen", "action_cancelled"), [])
        self.app.resolve_appeal(incident_id, "upheld", LEGAL)
        self.assertEqual(self._action(action_id)["status"], "executed")  # 仍不回滚
        self.assertEqual(self.app.incident_digest(incident_id)["status"], "已关闭")

    def test_concurrent_execute_and_appeal_has_single_explainable_order(self):
        # 真正并发地反复抢占同一把事务锁。无论调度把先手给了谁，
        # 唯一顺序由账本 seq 决定，且必须满足安全不变量：
        #   1) 同一动作绝不既外发（action_executed）又被冻结（action_frozen）；
        #   2) 申诉取得先手时，执行必被 409 拦截，无任何外发结果；
        #   3) 执行取得先手时，动作是 executed，随后申诉成立也不改写它；
        #   4) 申诉成立收口后终态唯一合法（executed 或 cancelled 之一）。
        observed = {"execute_first": 0, "appeal_first": 0}
        rounds = 30
        for _ in range(rounds):
            incident_id, action_id = self._approved_complaint()
            barrier = threading.Barrier(2)
            execute_error = []

            def run_execute():
                barrier.wait()
                try:
                    self.app.execute_action(action_id, LIASON)
                except AppError as error:
                    execute_error.append(error)

            def run_appeal():
                barrier.wait()
                self.app.open_appeal(incident_id, "误认", AGENT)

            t1 = threading.Thread(target=run_execute)
            t2 = threading.Thread(target=run_appeal)
            t1.start(); t2.start()
            t1.join(timeout=5); t2.join(timeout=5)
            self.assertFalse(t1.is_alive() or t2.is_alive(), "并发事务发生死锁")

            executed = bool(self._events_for(action_id, "action_executed"))
            frozen = bool(self._events_for(action_id, "action_frozen"))
            self.assertFalse(executed and frozen,
                             "同一动作不得既外发又被申诉冻结")
            self.assertEqual(executed, not execute_error)

            if executed:
                observed["execute_first"] += 1
                self.assertEqual(self._action(action_id)["status"], "executed")
            else:
                observed["appeal_first"] += 1
                # 申诉先手：执行被可解释地拒绝，无外发
                self.assertEqual(execute_error[0].status, 409)
                self.assertEqual(self._action(action_id)["status"], "frozen")

            self.app.resolve_appeal(incident_id, "upheld", LEGAL)
            final = self._action(action_id)["status"]
            self.assertEqual(final, "executed" if executed else "cancelled")

        # 至少发生过竞争；申诉先手这条最关键路径必须在多轮中被检验到
        self.assertEqual(sum(observed.values()), rounds)
        self.assertGreater(observed["appeal_first"], 0)

    # ---------------------------------------------------------- 重放与迟到回执
    def test_freeze_and_cancel_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app = SafeguardingApp(store_path=path)
            incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
            kept = app.propose_action(incident_id, "platform_complaint", AGENT)["action_id"]
            app.review_action(kept, "approve", LIASON)
            app.open_appeal(incident_id, "误认", AGENT)
            self.assertEqual(app.actions[kept]["status"], "frozen")

            reloaded = SafeguardingApp(store_path=path)  # 进程重启：重放账本
            self.assertEqual(reloaded.actions[kept]["status"], "frozen")
            self.assertEqual(reloaded.actions[kept]["reviewer"], LIASON["name"])
            with self.assertRaises(AppError):
                reloaded.execute_action(kept, LIASON)  # 重启不能绕过冻结

            reloaded.resolve_appeal(incident_id, "upheld", LEGAL)
            reloaded2 = SafeguardingApp(store_path=path)
            self.assertEqual(reloaded2.actions[kept]["status"], "cancelled")
            self.assertEqual(reloaded2.incident_digest(incident_id)["status"], "已关闭")
            with self.assertRaises(AppError):
                reloaded2.execute_action(kept, LIASON)  # 取消不可逆

    def test_late_platform_receipt_adds_fact_but_never_revives_or_reopens(self):
        incident_id, action_id = self._approved_complaint()
        self.app.open_appeal(incident_id, "误认", AGENT)
        self.app.resolve_appeal(incident_id, "upheld", LEGAL)
        self.assertEqual(self._action(action_id)["status"], "cancelled")
        before = self.app.incident_digest(incident_id)
        self.assertEqual(before["status"], "已关闭")

        # 案件关闭后平台迟到回执：凭 content_url 匹配既有事件，仅补事实
        late = {
            "callback_id": "CB-LATE",
            "receipt": {
                "receipt_id": "DY-LATE-1", "platform": "douyin", "status": "removed",
                "reported_at": "2026-09-20T09:00:00+08:00",
                "content_url": "https://video.example/comment/55",
            },
        }
        response = self.app.platform_callback(late)
        self.assertFalse(response["duplicate"])
        self.assertEqual(response["incident_id"], incident_id)

        digest = self.app.incident_digest(incident_id)
        self.assertEqual(digest["status"], "已关闭")  # 结论不变
        self.assertEqual(digest["close_reason"], before["close_reason"])
        self.assertEqual(self._action(action_id)["status"], "cancelled")  # 不复活
        receipt_ids = {r["receipt_id"] for r in digest["证据依据"]["platform_receipts"]}
        self.assertIn("DY-LATE-1", receipt_ids)  # 迟到事实已补充
        self.assertIn("deleted",
                      [e["state"] for e in digest["证据依据"]["evidence"]])
        with self.assertRaises(AppError):
            self.app.execute_action(action_id, LIASON)

    def test_digest_actions_and_notifications_show_consistent_freeze_state(self):
        incident_id, action_id = self._approved_complaint()
        self.app.open_appeal(incident_id, "误认", AGENT)
        digest = self.app.incident_digest(incident_id)
        self.assertEqual(digest["尚未完成的保护动作"]["frozen_action_ids"], [action_id])
        notifs = self.app.list_notifications(incident_id)
        freeze_notifs = [n for n in notifs if n.get("appeal_event") == "action_frozen"]
        self.assertEqual([n["action_id"] for n in freeze_notifs], [action_id])
        # 责任链中冻结事件在申诉事件之后、且引用同一动作
        chain = [c["type"] for c in digest["责任链"]]
        self.assertIn("action_frozen", chain)
        self.assertLess(chain.index("appeal_opened"), chain.index("action_frozen"))


class HttpContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = SafeguardingApp()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.app))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _request(self, method, path, payload=None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        request = Request(f"{self.base_url}{path}", data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_full_flow_over_http(self):
        status, body = self._request("POST", "/reports", threat_report(actor=AGENT))
        self.assertEqual(status, 201)
        incident_id = body["incident_id"]

        status, body = self._request(
            "GET", f"/incidents/{incident_id}/digest?as_role={quote('俱乐部保护专员')}")
        self.assertEqual(status, 200)
        self.assertTrue(body["尚未完成的保护动作"]["open_escalation"])

        status, body = self._request("POST", f"/incidents/{incident_id}/escalation/ack",
                                     {"actor": DUTY})
        self.assertEqual(status, 200)

        status, body = self._request("POST", f"/incidents/{incident_id}/actions",
                                     {"actor": AGENT, "action_type": "police_report"})
        self.assertEqual(status, 201)
        action_id = body["action_id"]
        self.assertEqual(body["required_reviewer_role"], "法务复核员")

        status, body = self._request("POST", f"/actions/{action_id}/review",
                                     {"actor": LIASON, "decision": "approve"})
        self.assertEqual(status, 403)
        status, body = self._request("POST", f"/actions/{action_id}/review",
                                     {"actor": LEGAL, "decision": "approve"})
        self.assertEqual(status, 200)
        status, body = self._request("POST", f"/actions/{action_id}/execute", {"actor": LEGAL})
        self.assertEqual(status, 200)
        self.assertIn("transfer_ref", body["result"])

        # 重复回调
        cb = {"callback_id": "CB-HTTP", "incident_id": incident_id,
              "receipt": {"receipt_id": "WB-1", "platform": "weibo", "status": "accepted"}}
        status, first = self._request("POST", "/callbacks/platform", cb)
        self.assertEqual(status, 200)
        self.assertFalse(first["duplicate"])
        status, second = self._request("POST", "/callbacks/platform", cb)
        self.assertTrue(second["duplicate"])

    def test_criticism_report_returns_200_without_incident(self):
        status, body = self._request("POST", "/reports", {
            "actor": AGENT, "victim_code": "ATH-020", "platform": "weibo",
            "content_url": "https://weibo.example/comment/2",
            "raw_excerpt": CRITICISM_TEXT, "severity": "criticism"})
        self.assertEqual(status, 200)
        self.assertIsNone(body["incident_id"])

    def test_unknown_route_is_404(self):
        status, _ = self._request("GET", "/unknown")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
