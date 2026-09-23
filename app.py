"""网络侵害事件受理与协同处置的业务核心。

设计要点：
- 所有事实以不可变事件落账（见 store.py），删除、改名、补充、撤回只追加记录；
- 普通批评只登记线索、不立事件；直接人身威胁自动按值班规则升级且只通知一次；
- 聚类只产生合并建议，须保护专员人工确认；
- 报案/平台投诉/公开澄清按职责分离提交、分角色复核，禁止自复核；
- 平台回调按 callback_id 幂等，重复回调不通知、不产生第二案件；
- 申诉期间限制敏感材料扩散并冻结对外动作；授权撤回不抹除责任链。

申诉与对外动作的竞态规则（全部以账本事件固化，重启可重放）：
- 申诉打开即把尚未执行的对外动作冻结（action_frozen），动作保留原审批依据，
  状态显式为 frozen，不再以 approved 示人；已执行动作只留事实、不回滚；
- 申诉驳回（dismissed）只恢复冻结时仍具备授权的动作（action_restored），
  授权在冻结期间被撤回的动作保持冻结态、按缺权不可执行；
- 申诉成立（upheld）不可逆地取消全部待执行动作（action_cancelled）并关闭事件；
- 所有写事务在应用级锁内串行，执行与申诉并发时以账本 seq 决定唯一先后：
  申诉先落账则执行必被冻结拦截，执行先落账则该动作既成事实（申诉不再取消它）；
- 授权撤回、事件合并、进程重启均不能绕过冻结；迟到平台回执只能补充既有事实，
  不得复活已取消动作或改变关闭结论。
"""

import copy
import functools
import hashlib
import threading
from datetime import datetime, timezone, timedelta

from domain import load_config
from store import EventStore, new_id

CST = timezone(timedelta(hours=8))

# 仅供联调的威胁线索提示词：最终等级仍以提交人填报、保护专员确认为准
_THREAT_HINTS = ("弄死", "杀死", "砍死", "打死", "别想走", "等着", "上门", "堵你", "炸死", "废了你")
_CRITICISM_HINTS = ("发挥", "状态", "战术", "换人", "表现", "踢得", "输球")


def now_iso():
    return datetime.now(CST).isoformat(timespec="seconds")


def content_hash(raw_excerpt):
    return hashlib.sha256((raw_excerpt or "").encode("utf-8")).hexdigest()


def suggest_severity(text):
    """联调用启发式：根据文本给严重度建议，不替代人工判定。"""
    if not text:
        return None
    if any(hint in text for hint in _THREAT_HINTS):
        return "direct_threat"
    if any(hint in text for hint in _CRITICISM_HINTS):
        return "criticism"
    return "abuse"


class AppError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _require(actor, allowed_roles):
    if not actor or "role" not in actor:
        raise AppError("缺少操作人信息 actor(name, role)")
    if actor["role"] not in allowed_roles:
        raise AppError(f"角色 {actor['role']} 无权执行该操作，允许角色：{'、'.join(allowed_roles)}", 403)


def _transaction(method):
    """把整个写操作包成一个事务：与其他事务互斥，事务内账本投影不会被并发观察到。"""

    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._tx_lock:
            return method(self, *args, **kwargs)

    return wrapped


# 尚未走到终态（执行/驳回/取消）的动作原始状态
_UNFINISHED_STATUSES = ("pending", "approved", "frozen")


class SafeguardingApp:
    SUBMIT_ROLES = ("当事人代理", "俱乐部保护专员")

    def __init__(self, config=None, store_path=None):
        self.config = config or load_config()
        self.store = EventStore(store_path)
        # 写事务级互斥：执行与申诉并发时，谁先在账本落 seq 谁为先，
        # 另一个请求在同一把锁上看到的是已更新的投影并据此被接受或拒绝。
        self._tx_lock = threading.RLock()
        self.reports = {}            # report_no -> 线索记录
        self.incidents = {}          # incident_id -> 事件投影
        self.actions = {}            # action_id -> 动作记录
        self.suggestions = {}        # suggestion_id -> 合并建议
        self.callbacks = {}          # callback_id -> 首次处理结果
        self.notifications = []      # 通知外发箱（抽象渠道）
        self._suggestion_keys = set()
        self._replay()
        self.store.subscribe(self._apply)

    # ------------------------------------------------------------------ 重放
    def _replay(self):
        for event in self.store.replay():
            self._apply(event)

    def _append(self, event_type, payload, event_id=None):
        event, _duplicate = self.store.append(event_type, payload, event_id=event_id)
        return event

    def _apply(self, event):
        handler = getattr(self, f"_on_{event['type']}", None)
        if handler:
            handler(event["payload"])

    # ---------------------------------------------------------- 线索报送/立案
    @_transaction
    def submit_report(self, payload, actor):
        _require(actor, self.SUBMIT_ROLES)
        severity = payload.get("severity")
        if not self.config.is_valid_severity(severity):
            raise AppError(f"未知严重度：{severity}")
        platform = payload.get("platform")
        if platform and platform not in self.config.platforms:
            raise AppError(f"未知平台：{platform}")
        if not payload.get("content_url"):
            raise AppError("线索必须包含受控引用 content_url")
        victim = payload.get("victim_code")
        if not victim:
            raise AppError("线索必须包含受侵害当事人 victim_code")

        report_no = new_id("rpt")
        raw = payload.get("raw_excerpt") or ""
        sha = content_hash(raw)
        scopes = payload.get("授权范围")
        if scopes is None:
            scopes = self.config.default_scopes
        unknown_scopes = set(scopes) - set(self.config.scopes)
        if unknown_scopes:
            raise AppError(f"未知授权范围：{sorted(unknown_scopes)}")

        report = {
            "report_no": report_no,
            "submitted_by": actor.get("name"),
            "submitter_role": actor["role"],
            "victim_code": victim,
            "platform": platform,
            "content_url": payload["content_url"],
            "content_sha256": sha,
            "severity": severity,
            "linked_accounts": payload.get("linked_accounts", []),
            "receipts": payload.get("receipts", []),
            "received_at": now_iso(),
            "decision": None,
            "incident_id": None,
        }
        self._append("report_received", {
            "report_no": report_no,
            "submitted_by": actor.get("name"),
            "submitter_role": actor["role"],
            "victim_code": victim,
            "platform": platform,
            "content_url": payload["content_url"],
            "content_sha256": sha,
            "severity": severity,
            "linked_accounts": payload.get("linked_accounts", []),
            "received_at": report["received_at"],
        })
        self.reports[report_no] = report

        # 普通批评：只登记观察，不立为保护事件，避免把批评误当网暴进入处置流程
        if not self.config.is_openable_severity(severity):
            report["decision"] = "不立案：普通批评，登记观察"
            self._append("report_screened", {
                "report_no": report_no, "decision": report["decision"], "at": now_iso(),
            })
            return {"report_no": report_no, "incident_id": None, "decision": report["decision"]}

        incident_id = self._open_incident(report, scopes)
        report["incident_id"] = incident_id
        return {"report_no": report_no, "incident_id": incident_id, "decision": "已立案"}

    def _open_incident(self, report, scopes):
        incident_id = new_id("inc")
        at = now_iso()
        self._append("incident_opened", {
            "incident_id": incident_id,
            "report_no": report["report_no"],
            "victim_code": report["victim_code"],
            "platform": report["platform"],
            "severity": report["severity"],
            "opened_at": at,
        })
        self._append("consent_granted", {
            "incident_id": incident_id, "scopes": scopes,
            "by": report["submitted_by"], "at": at,
        })
        self._append("evidence_registered", {
            "incident_id": incident_id,
            "evidence_id": new_id("ev"),
            "kind": "url",
            "content_ref": report["content_url"],
            "content_sha256": report["content_sha256"],
            "state": "online",
            "submitted_by": report["submitted_by"],
            "at": at,
            "note": "立案线索的受控引用",
        })
        for account in report["linked_accounts"]:
            self._append("account_linked", {
                "incident_id": incident_id,
                "link_id": new_id("acct"),
                "platform": account.get("platform"),
                "account_key": account.get("account_key"),
                "url": account.get("url"),
                "display_name": account.get("display_name"),
                "at": at,
            })
        for receipt in report["receipts"]:
            self._append("receipt_recorded", {
                "incident_id": incident_id,
                "receipt_id": receipt.get("receipt_id"),
                "platform": receipt.get("platform", report["platform"]),
                "status": receipt.get("status"),
                "reported_at": receipt.get("reported_at"),
                "via": "report",
                "at": now_iso(),
            })

        incident = self.incidents[incident_id]
        if self.config.should_escalate(report["severity"]):
            self._raise_escalation(incident_id, "立案等级为直接人身威胁，按值班规则自动升级")
        self._suggest_clusters_for(incident)
        return incident_id

    # ------------------------------------------------------------- 事件投影
    def _on_report_received(self, p):
        # submit_report 直接持有 report 对象；重放时重建
        if p["report_no"] not in self.reports:
            self.reports[p["report_no"]] = {
                "report_no": p["report_no"], "submitted_by": p["submitted_by"],
                "submitter_role": p["submitter_role"], "victim_code": p["victim_code"],
                "platform": p["platform"], "content_url": p["content_url"],
                "content_sha256": p["content_sha256"], "severity": p["severity"],
                "linked_accounts": p.get("linked_accounts", []), "receipts": [],
                "received_at": p["received_at"], "decision": None, "incident_id": None,
            }

    def _on_report_screened(self, p):
        report = self.reports.get(p["report_no"])
        if report:
            report["decision"] = p["decision"]

    def _on_incident_opened(self, p):
        self.incidents[p["incident_id"]] = {
            "incident_id": p["incident_id"],
            "report_nos": [p["report_no"]],
            "victim_code": p["victim_code"],
            "platform": p["platform"],
            "severity": p["severity"],
            "opened_at": p["opened_at"],
            "closed_at": None,
            "close_reason": None,
            "consent_scopes": [],
            "evidence": [],
            "accounts": [],
            "receipts": [],
            "actions": [],
            "escalation": None,
            "appeal": None,
            "merged_into": None,
            "absorbed": [],
            "false_report_upheld": False,
        }
        report = self.reports.get(p["report_no"])
        if report is not None and report.get("incident_id") is None:
            report["incident_id"] = p["incident_id"]
            report["decision"] = "已立案"

    def _on_consent_granted(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for scope in p["scopes"]:
                if scope not in inc["consent_scopes"]:
                    inc["consent_scopes"].append(scope)

    def _on_consent_revoked(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["consent_scopes"] = [s for s in inc["consent_scopes"] if s not in p["scopes"]]

    def _on_evidence_registered(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["evidence"].append({
                "evidence_id": p["evidence_id"], "kind": p["kind"],
                "content_ref": p["content_ref"], "content_sha256": p["content_sha256"],
                "state": p.get("state", "online"), "submitted_by": p.get("submitted_by"),
                "at": p["at"], "note": p.get("note", ""),
            })

    def _on_evidence_supplemented(self, p):
        self._on_evidence_registered(p)

    def _on_content_state_changed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for ev in inc["evidence"]:
                if ev["evidence_id"] == p["evidence_id"]:
                    ev["state"] = p["new_state"]

    def _on_account_linked(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["accounts"].append({
                "link_id": p["link_id"], "platform": p["platform"],
                "account_key": p["account_key"], "url": p.get("url"),
                "display_name": p.get("display_name"),
                "name_history": ([{"name": p.get("display_name"), "at": p["at"]}]
                                 if p.get("display_name") else []),
            })

    def _on_account_renamed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for acct in inc["accounts"]:
                if acct["platform"] == p["platform"] and acct["account_key"] == p["account_key"]:
                    acct["name_history"].append({"name": p["new_name"], "at": p["at"]})
                    acct["display_name"] = p["new_name"]

    def _on_receipt_recorded(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["receipts"] = [r for r in inc["receipts"] if r["receipt_id"] != p["receipt_id"]]
            inc["receipts"].append({
                "receipt_id": p["receipt_id"], "platform": p["platform"],
                "status": p["status"], "reported_at": p.get("reported_at"),
                "via": p.get("via", "callback"), "at": p["at"],
            })

    def _on_escalation_raised(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["escalation"] = {
                "escalation_id": p["escalation_id"], "reason": p["reason"],
                "raised_at": p["at"], "status": "open",
                "last_confirmed_at": p["at"], "acknowledged_at": None,
                "acknowledged_by": None,
            }

    def _on_escalation_confirmed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["escalation"]:
            inc["escalation"]["last_confirmed_at"] = p["at"]

    def _on_escalation_acknowledged(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["escalation"]:
            inc["escalation"]["status"] = "acknowledged"
            inc["escalation"]["acknowledged_at"] = p["at"]
            inc["escalation"]["acknowledged_by"] = p["by"]

    def _on_severity_confirmed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["severity"] = p["severity"]

    def _on_merge_suggested(self, p):
        sugg = {
            "suggestion_id": p["suggestion_id"], "incident_ids": list(p["incident_ids"]),
            "reason": p["reason"], "status": "open",
            "created_at": p["created_at"], "resolved_by": None, "resolved_at": None,
            "merged_into": None,
        }
        self.suggestions[p["suggestion_id"]] = sugg
        self._suggestion_keys.add(self._pair_key(p["incident_ids"]))

    def _on_suggestion_resolved(self, p):
        sugg = self.suggestions.get(p["suggestion_id"])
        if sugg:
            sugg["status"] = p["decision"]
            sugg["resolved_by"] = p["by"]
            sugg["resolved_at"] = p["at"]
            sugg["merged_into"] = p.get("merged_into")

    def _on_incidents_merged(self, p):
        survivor = self.incidents.get(p["survivor_id"])
        absorbed = self.incidents.get(p["merged_id"])
        if survivor and absorbed:
            survivor["absorbed"].append(p["merged_id"])
            absorbed["merged_into"] = p["survivor_id"]

    def _on_appeal_opened(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["appeal"] = {"reason": p["reason"], "opened_by": p["by"],
                             "opened_at": p["at"], "status": "open",
                             "resolved_at": None, "decision": None}

    def _on_appeal_resolved(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["appeal"]:
            inc["appeal"]["status"] = "resolved"
            inc["appeal"]["decision"] = p["decision"]
            inc["appeal"]["resolved_at"] = p["at"]
            if p["decision"] == "upheld":
                inc["false_report_upheld"] = True

    def _on_incident_closed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["closed_at"] = p["at"]
            inc["close_reason"] = p["reason"]

    def _on_action_proposed(self, p):
        self.actions[p["action_id"]] = {
            "action_id": p["action_id"], "incident_id": p["incident_id"],
            "action_type": p["action_type"], "params": p.get("params", {}),
            "proposed_by": p["proposed_by"], "proposed_by_role": p["proposed_by_role"],
            "required_reviewer_role": p["required_reviewer_role"],
            "required_scopes": p.get("required_scopes", []),
            "status": "pending", "reviewer": None, "reviewer_role": None,
            "review_reason": None, "reviewed_at": None,
            "executed_at": None, "result": None, "proposed_at": p["at"],
            # 冻结轨迹：申诉打开时记录冻结前状态与当时审批依据，
            # 恢复/取消均只追加，不抹除原审批与冻结事实。
            "frozen_at": None, "frozen_by": None, "frozen_reason": None,
            "frozen_from_status": None, "frozen_scopes": None,
            "restored_at": None, "restored_from_status": None,
            "cancelled_at": None, "cancelled_by": None, "cancel_reason": None,
        }
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["actions"].append(p["action_id"])

    def _on_action_reviewed(self, p):
        action = self.actions.get(p["action_id"])
        if action:
            action["status"] = "approved" if p["decision"] == "approve" else "rejected"
            action["reviewer"] = p["reviewer"]
            action["reviewer_role"] = p["reviewer_role"]
            action["review_reason"] = p.get("reason")
            action["reviewed_at"] = p["at"]

    def _on_action_frozen(self, p):
        action = self.actions.get(p["action_id"])
        if action and action["status"] in ("pending", "approved"):
            action["frozen_from_status"] = action["status"]
            action["frozen_scopes"] = list(p.get("required_scopes", action["required_scopes"]))
            action["frozen_at"] = p["at"]
            action["frozen_by"] = p.get("by")
            action["frozen_reason"] = p.get("reason")
            action["status"] = "frozen"

    def _on_action_restored(self, p):
        action = self.actions.get(p["action_id"])
        if not action or action["status"] != "frozen":
            return
        if p.get("reinstated") is False:
            # 驳回但授权已撤回：动作保持冻结，仅登记未恢复原因（可重放）。
            action.setdefault("restore_denials", []).append({
                "at": p["at"], "missing_scopes": list(p.get("missing_scopes", [])),
                "reason": p.get("reason"),
            })
            return
        # 只恢复冻结前的待执行状态；审批依据（reviewer 等）原样保留。
        action["restored_from_status"] = action["frozen_from_status"]
        action["restored_at"] = p["at"]
        action["status"] = action["frozen_from_status"] or "pending"

    def _on_action_cancelled(self, p):
        action = self.actions.get(p["action_id"])
        if action and action["status"] in ("pending", "approved", "frozen"):
            action["status"] = "cancelled"
            action["cancelled_at"] = p["at"]
            action["cancelled_by"] = p.get("by")
            action["cancel_reason"] = p.get("reason")

    def _on_action_executed(self, p):
        action = self.actions.get(p["action_id"])
        if action:
            action["status"] = "executed"
            action["executed_at"] = p["at"]
            action["result"] = p.get("result", {})
            if p.get("receipt"):
                inc = self.incidents.get(action["incident_id"])
                if inc:
                    receipt = p["receipt"]
                    inc["receipts"] = [r for r in inc["receipts"]
                                       if r["receipt_id"] != receipt.get("receipt_id")]
                    inc["receipts"].append({"via": "action", "at": p["at"], **receipt})

    def _on_notification_sent(self, p):
        self.notifications.append(p)

    def _on_callback_processed(self, p):
        if p["callback_id"] not in self.callbacks:
            self.callbacks[p["callback_id"]] = p["result"]

    # ------------------------------------------------------------- 严重度确认
    @_transaction
    def confirm_severity(self, incident_id, severity, actor):
        _require(actor, ("俱乐部保护专员", "俱乐部值班主管"))
        inc = self._get_open_incident(incident_id)
        if not self.config.is_valid_severity(severity):
            raise AppError(f"未知严重度：{severity}")
        self._append("severity_confirmed", {
            "incident_id": incident_id, "severity": severity,
            "by": actor.get("name"), "at": now_iso(),
        })
        if self.config.should_escalate(severity):
            esc = inc["escalation"]
            if esc and esc["status"] == "open":
                # 同一值班周期内重复确认：只刷新确认时间，不再升级、不再次通知
                self._append("escalation_confirmed", {
                    "incident_id": incident_id, "at": now_iso(),
                })
            else:
                self._raise_escalation(incident_id, "等级经确认升至直接人身威胁")

    # ------------------------------------------------------------- 值班升级
    def _notify(self, incident_id, channel, to_role, reason, at, **extra):
        payload = {"notif_id": new_id("ntf"), "incident_id": incident_id,
                   "channel": channel, "to_role": to_role, "reason": reason, "at": at}
        payload.update(extra)
        self._append("notification_sent", payload)

    def _raise_escalation(self, incident_id, reason):
        inc = self._get_open_incident(incident_id)
        if inc["escalation"] and inc["escalation"]["status"] == "open":
            return inc["escalation"]["escalation_id"]
        escalation_id = new_id("esc")
        at = now_iso()
        self._append("escalation_raised", {
            "incident_id": incident_id, "escalation_id": escalation_id,
            "reason": reason, "at": at,
        })
        for role in self.config.duty["通知角色"]:
            self._notify(incident_id, "duty", role, reason, at,
                         escalation_id=escalation_id)
        return escalation_id

    @_transaction
    def acknowledge_escalation(self, incident_id, actor):
        _require(actor, ("俱乐部值班主管",))
        inc = self._get_incident(incident_id)
        if not inc["escalation"] or inc["escalation"]["status"] != "open":
            raise AppError("该事件没有待响应的值班升级")
        self._append("escalation_acknowledged", {
            "incident_id": incident_id, "by": actor.get("name"), "at": now_iso(),
        })

    # ------------------------------------------------------------------ 证据
    @_transaction
    def add_evidence(self, incident_id, payload, actor):
        _require(actor, self.SUBMIT_ROLES + ("平台联络员", "法务复核员"))
        inc = self._get_open_incident(incident_id)
        self._assert_not_appealed(inc)
        if not payload.get("content_ref"):
            raise AppError("证据补充必须提供受控引用 content_ref，不接受原始内容入库")
        evidence_id = new_id("ev")
        self._append("evidence_registered", {
            "incident_id": incident_id, "evidence_id": evidence_id,
            "kind": payload.get("kind", "supplement"),
            "content_ref": payload["content_ref"],
            "content_sha256": payload.get("content_sha256")
                              or content_hash(payload.get("raw_excerpt", "")),
            "state": payload.get("state", "online"),
            "submitted_by": actor.get("name"), "at": now_iso(),
            "note": payload.get("note", "证据补充"),
        })
        return {"evidence_id": evidence_id}

    @_transaction
    def link_account(self, incident_id, payload, actor):
        _require(actor, self.SUBMIT_ROLES + ("平台联络员",))
        inc = self._get_open_incident(incident_id)
        if not payload.get("account_key"):
            raise AppError("关联账号必须包含 platform 与 account_key")
        link_id = new_id("acct")
        self._append("account_linked", {
            "incident_id": incident_id, "link_id": link_id,
            "platform": payload.get("platform"), "account_key": payload["account_key"],
            "url": payload.get("url"), "display_name": payload.get("display_name"),
            "at": now_iso(),
        })
        self._suggest_clusters_for(inc)
        return {"link_id": link_id}

    # ------------------------------------------------------------------ 聚类
    def _pair_key(self, incident_ids):
        return "|".join(sorted(incident_ids))

    def _suggest_clusters_for(self, inc):
        """只生成合并建议；任何合并都必须由保护专员确认。"""
        candidates = []
        for other_id, other in self.incidents.items():
            if other_id == inc["incident_id"] or other.get("merged_into") or other.get("closed_at"):
                continue
            reason = None
            same_victim = other["victim_code"] == inc["victim_code"]
            if same_victim:
                old_hashes = {e["content_sha256"] for e in other["evidence"] if e["content_sha256"]}
                new_hashes = {e["content_sha256"] for e in inc["evidence"] if e["content_sha256"]}
                if old_hashes & new_hashes:
                    reason = "同一当事人且内容哈希一致"
            if reason is None:
                old_keys = {(a["platform"], a["account_key"]) for a in other["accounts"]}
                new_keys = {(a["platform"], a["account_key"]) for a in inc["accounts"]}
                if old_keys & new_keys:
                    reason = "共享同一平台关联账号"
            if reason:
                candidates.append((other_id, reason))
        for other_id, reason in candidates:
            pair = [inc["incident_id"], other_id]
            if self._pair_key(pair) in self._suggestion_keys:
                continue
            self._append("merge_suggested", {
                "suggestion_id": new_id("sug"),
                "incident_ids": pair,
                "reason": reason,
                "created_at": now_iso(),
            })

    @_transaction
    def resolve_suggestion(self, suggestion_id, decision, actor, target_incident=None):
        _require(actor, ("俱乐部保护专员",))
        sugg = self.suggestions.get(suggestion_id)
        if not sugg:
            raise AppError("合并建议不存在", 404)
        if sugg["status"] != "open":
            raise AppError("该建议已处理")
        if decision not in ("accept", "reject"):
            raise AppError("decision 仅支持 accept/reject")
        merged_into = None
        if decision == "accept":
            merged_into = target_incident or sugg["incident_ids"][0]
            source_id = sugg["incident_ids"][1] if merged_into == sugg["incident_ids"][0] else sugg["incident_ids"][0]
            if merged_into not in sugg["incident_ids"]:
                raise AppError("合并目标必须是建议涉及的事件之一")
            self._get_open_incident(merged_into)
            self._get_open_incident(source_id)
            # 事件合并不能绕过冻结：申诉存续或尚有冻结动作时禁止合并，
            # 避免冻结动作随事件并入主事件后脱离申诉/授权语义。
            for candidate_id in (merged_into, source_id):
                candidate = self.incidents[candidate_id]
                if self._appeal_open(candidate):
                    raise AppError(f"事件 {candidate_id} 申诉存续期间不得合并", 409)
                if any(self.actions[a]["status"] == "frozen" for a in candidate["actions"]):
                    raise AppError(f"事件 {candidate_id} 存在申诉冻结动作，解冻前不得合并", 409)
            self._append("incidents_merged", {
                "survivor_id": merged_into, "merged_id": source_id,
                "by": actor.get("name"), "at": now_iso(),
            })
        self._append("suggestion_resolved", {
            "suggestion_id": suggestion_id, "decision": decision,
            "by": actor.get("name"), "at": now_iso(), "merged_into": merged_into,
        })
        return {"status": decision, "merged_into": merged_into}

    # ------------------------------------------------------------------ 授权
    @_transaction
    def grant_consent(self, incident_id, scopes, actor):
        _require(actor, ("当事人代理",))
        inc = self._get_incident(incident_id)
        unknown = set(scopes) - set(self.config.scopes)
        if unknown:
            raise AppError(f"未知授权范围：{sorted(unknown)}")
        self._append("consent_granted", {
            "incident_id": incident_id, "scopes": scopes,
            "by": actor.get("name"), "at": now_iso(),
        })
        # 申诉驳回后因缺权未恢复的冻结动作，在重新授权齐备时自动恢复，
        # 原审批依据不变；申诉仍存续时绝不恢复。
        if not self._appeal_open(inc):
            self._recover_frozen_with_consent(inc, actor.get("name"))
        return {"scopes": inc["consent_scopes"]}

    def _recover_frozen_with_consent(self, inc, by):
        at = now_iso()
        for action_id in inc["actions"]:
            action = self.actions[action_id]
            if action["status"] != "frozen" or action["frozen_from_status"] != "approved":
                continue
            missing = [s for s in action["required_scopes"] if s not in inc["consent_scopes"]]
            if missing:
                continue
            self._append("action_restored", {
                "action_id": action_id, "incident_id": inc["incident_id"],
                "reinstated": True,
                "reason": "重新授权齐备，恢复冻结前已批准状态",
                "by": by, "at": at,
            })

    @_transaction
    def revoke_consent(self, incident_id, scopes, actor):
        _require(actor, ("当事人代理",))
        inc = self._get_incident(incident_id)
        unknown = set(scopes) - set(self.config.scopes)
        if unknown:
            raise AppError(f"未知授权范围：{sorted(unknown)}")
        # 申诉或司法移交存续期间，证据留存授权不可撤回（其余授权仍可撤回）
        if "evidence_storage" in scopes and (inc["appeal"] and inc["appeal"]["status"] == "open"):
            raise AppError("误报申诉存续期间不可撤回证据留存授权")
        if "evidence_storage" in scopes and self._has_executed(incident_id, "police_report"):
            raise AppError("已报案移交的事件处于司法程序中，证据留存授权不可单独撤回")
        self._append("consent_revoked", {
            "incident_id": incident_id, "scopes": scopes,
            "by": actor.get("name"), "at": now_iso(),
        })
        # 授权撤回不改变冻结状态本身：冻结由申诉事件管辖。
        # 已批准动作仅在视图层因缺权显示 blocked；冻结动作保持 frozen。
        return {"scopes": inc["consent_scopes"]}

    def _has_executed(self, incident_id, action_type):
        return any(self.actions[a]["action_type"] == action_type
                   and self.actions[a]["status"] == "executed"
                   for a in self.incidents[incident_id]["actions"])

    # ------------------------------------------------------------------ 动作
    EXTERNAL_ACTIONS = ("platform_complaint", "police_report", "public_statement")

    def _appeal_open(self, inc):
        return bool(inc["appeal"] and inc["appeal"]["status"] == "open")

    @_transaction
    def propose_action(self, incident_id, action_type, actor, params=None):
        _require(actor, self.SUBMIT_ROLES)
        inc = self._get_open_incident(incident_id)
        if action_type not in self.config.actions:
            raise AppError(f"未知处置动作：{action_type}")
        if action_type in self.EXTERNAL_ACTIONS and self._appeal_open(inc):
            raise AppError("误报申诉期间不得发起新的对外动作")
        action_id = new_id("act")
        self._append("action_proposed", {
            "action_id": action_id, "incident_id": incident_id,
            "action_type": action_type, "params": params or {},
            "proposed_by": actor.get("name"), "proposed_by_role": actor["role"],
            "required_reviewer_role": self.config.reviewer_role_for(action_type),
            "required_scopes": self.config.required_scopes_for(action_type),
            "at": now_iso(),
        })
        return {"action_id": action_id,
                "required_reviewer_role": self.config.reviewer_role_for(action_type)}

    @_transaction
    def review_action(self, action_id, decision, actor, reason=None):
        action = self.actions.get(action_id)
        if not action:
            raise AppError("处置动作不存在", 404)
        inc = self._get_open_incident(action["incident_id"])
        if action["status"] != "pending":
            raise AppError(f"动作当前状态为{self._action_status_name(action['status'])}，不能复核")
        if decision not in ("approve", "reject"):
            raise AppError("decision 仅支持 approve/reject")
        if actor["role"] != action["required_reviewer_role"]:
            raise AppError(
                f"该动作须由 {action['required_reviewer_role']} 复核", 403)
        if self.config.separation["禁止自复核"] and actor.get("name") == action["proposed_by"]:
            raise AppError("提交人不能复核自己发起的动作", 403)
        self._append("action_reviewed", {
            "action_id": action_id, "incident_id": action["incident_id"],
            "decision": decision,
            "reviewer": actor.get("name"), "reviewer_role": actor["role"],
            "reason": reason, "at": now_iso(),
        })
        return {"action_id": action_id, "status": "approved" if decision == "approve" else "rejected"}

    @staticmethod
    def _action_status_name(status):
        return {
            "pending": "待复核", "approved": "已批准待执行", "frozen": "申诉冻结中",
            "executed": "已执行", "rejected": "已驳回", "cancelled": "已取消",
        }.get(status, status)

    @_transaction
    def execute_action(self, action_id, actor):
        action = self.actions.get(action_id)
        if not action:
            raise AppError("处置动作不存在", 404)
        inc = self._get_open_incident(action["incident_id"])
        # 顺序解释：进入事务后读到的投影即账本最新状态。
        # 若并发申诉已先落账，动作必为 frozen，在此被拦截——绝不外发。
        if action["status"] == "frozen":
            raise AppError(
                f"动作已因误报申诉冻结（{action.get('frozen_reason') or '申诉中'}），"
                "须待法务裁定；申诉未获支持前不得执行", 409)
        if action["status"] == "cancelled":
            raise AppError("动作已随误报申诉成立被取消，不可执行", 409)
        if action["status"] != "approved":
            raise AppError("仅已复核通过的动作可以执行")
        missing = [s for s in action["required_scopes"] if s not in inc["consent_scopes"]]
        if missing:
            names = "、".join(self.config.scopes[s]["名称"] for s in missing)
            raise AppError(f"当事人当前授权不足，缺少：{names}；动作保持已批准待执行", 409)
        if action["action_type"] in self.EXTERNAL_ACTIONS and self._appeal_open(inc):
            # 兜底：即使动作尚未被冻结事件覆盖（理论上不会发生），申诉先手也阻断外发。
            raise AppError("误报申诉期间不得执行对外动作", 409)

        at = now_iso()
        receipt = None
        result = {"executed_by": actor.get("name")}
        if action["action_type"] == "platform_complaint":
            platform = action["params"].get("platform") or inc["platform"]
            receipt = {
                "receipt_id": new_id("RCP"),
                "platform": platform,
                "status": "accepted",
                "reported_at": at,
            }
            result["complaint_ref"] = receipt["receipt_id"]
        elif action["action_type"] == "police_report":
            result["transfer_ref"] = new_id("POL")
        elif action["action_type"] == "public_statement":
            result["statement_ref"] = new_id("STM")
        else:
            result["note"] = "内部保护动作已落实"
        self._append("action_executed", {
            "action_id": action_id, "incident_id": action["incident_id"],
            "at": at, "result": result, "receipt": receipt,
        })
        return {"action_id": action_id, "status": "executed", "result": result}

    # ------------------------------------------------------------------ 申诉
    @_transaction
    def open_appeal(self, incident_id, reason, actor):
        _require(actor, self.SUBMIT_ROLES)
        inc = self._get_open_incident(incident_id)
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("该事件已在申诉中")
        at = now_iso()
        self._append("appeal_opened", {
            "incident_id": incident_id, "reason": reason,
            "by": actor.get("name"), "at": at,
        })
        # 申诉取得先手：把所有尚未执行的对外动作立即冻结为账本事实。
        # 原审批/复核依据（reviewer、review_reason、required_scopes）原样保留，
        # 已执行动作不在此列——只保留事实，绝不回滚。
        frozen = []
        for action_id in inc["actions"]:
            action = self.actions[action_id]
            if (action["action_type"] in self.EXTERNAL_ACTIONS
                    and action["status"] in ("pending", "approved")):
                self._append("action_frozen", {
                    "action_id": action_id, "incident_id": incident_id,
                    "from_status": action["status"],
                    "required_scopes": list(action["required_scopes"]),
                    "reason": "误报申诉打开，冻结尚未执行的对外动作",
                    "by": actor.get("name"), "at": at,
                })
                frozen.append(action_id)
                # 通知该动作的复核角色：已批准动作被冻结、暂不可执行
                self._notify(incident_id, "appeal", action["required_reviewer_role"],
                             f"对外动作 {action['action_type']} 因误报申诉冻结", at,
                             action_id=action_id, appeal_event="action_frozen")
        # 通知法务：有待裁定申诉并已冻结对外动作
        self._notify(incident_id, "appeal", "法务复核员",
                     f"误报申诉已打开，冻结 {len(frozen)} 个对外动作，待裁定", at,
                     appeal_event="appeal_opened", frozen_action_ids=frozen)
        return {"status": "申诉中", "frozen_actions": frozen}

    @_transaction
    def resolve_appeal(self, incident_id, decision, actor, note=None):
        _require(actor, ("法务复核员",))
        inc = self._get_incident(incident_id)
        if not inc["appeal"] or inc["appeal"]["status"] != "open":
            raise AppError("该事件没有待裁定的申诉")
        if decision not in ("upheld", "dismissed"):
            raise AppError("decision 仅支持 upheld（误报成立）/dismissed（申诉驳回）")
        at = now_iso()
        self._append("appeal_resolved", {
            "incident_id": incident_id, "decision": decision,
            "by": actor.get("name"), "at": at, "note": note,
        })
        if decision == "upheld":
            # 申诉成立：不可逆地取消全部待执行项（含未走完复核的内部动作），
            # 已执行/已驳回动作不动；随后关闭案件。
            cancelled = []
            for action_id in inc["actions"]:
                action = self.actions[action_id]
                if action["status"] in _UNFINISHED_STATUSES:
                    self._append("action_cancelled", {
                        "action_id": action_id, "incident_id": incident_id,
                        "reason": "误报申诉成立，取消待执行动作（不回滚已完成动作）",
                        "by": actor.get("name"), "at": at,
                    })
                    cancelled.append(action_id)
                    self._notify(incident_id, "appeal", action["required_reviewer_role"],
                                 f"对外动作 {action['action_type']} 随申诉成立被取消", at,
                                 action_id=action_id, appeal_event="action_cancelled")
            self._append("incident_closed", {
                "incident_id": incident_id,
                "reason": "误报申诉成立，按误报关闭（责任链留存）",
                "by": actor.get("name"), "at": now_iso(),
            })
            self._notify(incident_id, "appeal", "俱乐部保护专员",
                         f"误报申诉成立，取消 {len(cancelled)} 个待执行动作并关闭事件", at,
                         appeal_event="appeal_upheld", cancelled_action_ids=cancelled)
        else:
            # 申诉驳回：只恢复仍具备授权的动作。
            # pending（尚未复核）动作恢复待复核；approved 动作须当前授权仍在，
            # 冻结期间授权被撤回的，保持冻结并登记未恢复原因，待重新授权后再恢复。
            for action_id in inc["actions"]:
                action = self.actions[action_id]
                if action["status"] != "frozen":
                    continue
                missing = [s for s in action["required_scopes"]
                           if s not in inc["consent_scopes"]]
                if action["frozen_from_status"] == "approved" and missing:
                    self._append("action_restored", {
                        "action_id": action_id, "incident_id": incident_id,
                        "reinstated": False,
                        "missing_scopes": missing,
                        "reason": "申诉驳回但授权已撤回，动作暂不恢复",
                        "by": actor.get("name"), "at": at,
                    })
                    self._notify(incident_id, "appeal", action["required_reviewer_role"],
                                 f"申诉驳回，但动作 {action['action_type']} 授权不足仍冻结", at,
                                 action_id=action_id, appeal_event="restore_withheld",
                                 missing_scopes=missing)
                else:
                    self._append("action_restored", {
                        "action_id": action_id, "incident_id": incident_id,
                        "reinstated": True,
                        "reason": "申诉驳回，恢复冻结前状态",
                        "by": actor.get("name"), "at": at,
                    })
                    self._notify(incident_id, "appeal", action["required_reviewer_role"],
                                 f"申诉驳回，动作 {action['action_type']} 恢复可执行", at,
                                 action_id=action_id, appeal_event="action_restored")
            self._notify(incident_id, "appeal", "俱乐部保护专员",
                         "误报申诉驳回，保护处置恢复", at, appeal_event="appeal_dismissed")

    @_transaction
    def close_incident(self, incident_id, reason, actor):
        _require(actor, ("俱乐部保护专员", "法务复核员"))
        inc = self._get_open_incident(incident_id)
        # 可执行待办只计 pending/approved；冻结与已取消都不是可执行项。
        pending = [a for a in inc["actions"]
                   if self.actions[a]["status"] in ("pending", "approved")]
        frozen = [a for a in inc["actions"] if self.actions[a]["status"] == "frozen"]
        if inc["escalation"] and inc["escalation"]["status"] == "open":
            raise AppError("值班升级尚未响应，不能关闭事件")
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("申诉尚未裁定，不能关闭事件")
        if frozen:
            raise AppError(f"尚有 {len(frozen)} 个申诉冻结动作未解冻（需恢复执行或取消），不能关闭事件")
        if pending:
            raise AppError(f"尚有 {len(pending)} 个保护动作未完成，不能关闭事件")
        self._append("incident_closed", {
            "incident_id": incident_id, "reason": reason or "保护动作完成，关闭",
            "by": actor.get("name"), "at": now_iso(),
        })

    # ------------------------------------------------------------------ 回调
    @_transaction
    def platform_callback(self, payload):
        """平台/采集回调。以 callback_id 幂等：重复回调不通知、不产生第二案件。

        迟到回执（事件已关闭或动作已取消后到达）只允许补充既有事实
        （回执、内容状态、账号改名），既不复活已取消动作，也不改变关闭结论；
        回调永远不会仅凭内容另立案件。
        """
        callback_id = payload.get("callback_id")
        if not callback_id:
            raise AppError("回调必须携带 callback_id")
        if callback_id in self.callbacks:
            first = self.callbacks[callback_id]
            return {"duplicate": True, "callback_id": callback_id, **first}

        incident = self._resolve_callback_incident(payload)
        if incident is None:
            raise AppError("回调未匹配到既有事件，须先经当事人或授权代理报送立案", 404)
        # 已被合并的事件：迟到事实归集到主事件，保证主事件摘要/责任链一致。
        # 证据/账号可能仍登记在被吸收事件上，故沿合并链在主事件及其吸收事件内查属主。
        owner_chain = []
        cur, seen = incident, set()
        while cur is not None and cur["incident_id"] not in seen:
            seen.add(cur["incident_id"])
            owner_chain.append(cur)
            cur = self.incidents.get(cur["merged_into"]) if cur.get("merged_into") else None
        survivor = owner_chain[-1]
        for absorbed_id in survivor.get("absorbed", []):
            absorbed = self.incidents.get(absorbed_id)
            if absorbed and absorbed not in owner_chain:
                owner_chain.append(absorbed)
        incident_id = survivor["incident_id"]
        at = now_iso()
        attached = []

        def _find_evidence(url):
            for candidate in owner_chain:
                evidence = self._evidence_for(candidate, url)
                if evidence:
                    return candidate, evidence
            return None, None

        def _find_account(platform, account_key):
            for candidate in owner_chain:
                match = next((a for a in candidate["accounts"]
                              if a["platform"] == platform
                              and a["account_key"] == account_key), None)
                if match:
                    return candidate, match
            return None, None

        receipt = payload.get("receipt")
        if receipt and receipt.get("receipt_id"):
            self._append("receipt_recorded", {
                "incident_id": incident_id,
                "receipt_id": receipt["receipt_id"],
                "platform": receipt.get("platform", payload.get("platform")),
                "status": receipt.get("status"),
                "reported_at": receipt.get("reported_at", at),
                "via": "callback", "at": at,
            })
            attached.append("receipt")
            if receipt.get("status") == "removed":
                owner, evidence = _find_evidence(receipt.get("content_url"))
                if evidence:
                    self._append("content_state_changed", {
                        # 写在真正持有证据的事件上；被吸收事件已在主事件责任链内。
                        "incident_id": owner["incident_id"],
                        "evidence_id": evidence["evidence_id"],
                        "old_state": evidence["state"], "new_state": "deleted",
                        "source": "platform_callback", "at": at,
                    })
                    attached.append("content_deleted")

        account = payload.get("account")
        if account and account.get("account_key"):
            owner, matched = _find_account(
                account.get("platform"), account["account_key"])
            if matched:
                new_name = account.get("display_name")
                if new_name and new_name != matched["display_name"]:
                    self._append("account_renamed", {
                        "incident_id": owner["incident_id"],
                        "platform": matched["platform"],
                        "account_key": matched["account_key"],
                        "old_name": matched["display_name"],
                        "new_name": new_name, "at": at,
                    })
                    attached.append("account_renamed")
            else:
                self._append("account_linked", {
                    "incident_id": incident_id, "link_id": new_id("acct"),
                    "platform": account.get("platform", payload.get("platform")),
                    "account_key": account["account_key"], "url": account.get("url"),
                    "display_name": account.get("display_name"), "at": at,
                })
                attached.append("account_linked")

        # 回调附件不产生任何通知，也绝不另立案件
        result = {"duplicate": False, "callback_id": callback_id,
                  "incident_id": incident_id, "attached": attached}
        stored = {k: v for k, v in result.items() if k != "duplicate"}
        self.callbacks[callback_id] = stored
        # 事件化记录，保证账本重放（含重启）后幂等索引仍然有效
        self._append("callback_processed", {"callback_id": callback_id, "result": stored, "at": at})
        return result

    def _resolve_callback_incident(self, payload):
        explicit = payload.get("incident_id")
        if explicit and explicit in self.incidents:
            return self.incidents[explicit]
        receipt = payload.get("receipt") or {}
        receipt_id = receipt.get("receipt_id")
        if receipt_id:
            for inc in self.incidents.values():
                if any(r["receipt_id"] == receipt_id for r in inc["receipts"]):
                    return inc
        url = receipt.get("content_url") or payload.get("content_url")
        if url:
            for inc in self.incidents.values():
                if any(e["content_ref"] == url for e in inc["evidence"]):
                    return inc
        return None

    def _evidence_for(self, incident, url):
        if not url:
            return None
        return next((e for e in incident["evidence"] if e["content_ref"] == url), None)

    # ------------------------------------------------------------------ 查询
    def _get_incident(self, incident_id):
        inc = self.incidents.get(incident_id)
        if not inc:
            raise AppError("事件不存在", 404)
        return inc

    def _get_open_incident(self, incident_id):
        inc = self._get_incident(incident_id)
        if inc.get("merged_into"):
            raise AppError(f"该事件已合并入 {inc['merged_into']}，请在主事件上操作", 409)
        if inc.get("closed_at"):
            raise AppError("事件已关闭，不可再变更", 409)
        return inc

    def _assert_not_appealed(self, inc):
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("申诉期间限制敏感材料扩散，须先由法务复核员裁定")

    def _status_of(self, inc):
        if inc.get("closed_at"):
            return "已关闭"
        if inc.get("merged_into"):
            return "已关闭"
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            return "申诉中"
        if self._has_executed(inc["incident_id"], "police_report"):
            return "已移交"
        if any(self.actions[a]["status"] == "pending" for a in inc["actions"]):
            return "待复核"
        if inc["actions"] or inc["escalation"]:
            return "保护中"
        return "已受理"

    @_transaction
    def incident_digest(self, incident_id, as_role=None):
        """保护专员视角的统一视图：证据依据、处置决定、授权范围、待办保护动作。"""
        inc = self._get_incident(incident_id)
        appeal_open = inc["appeal"] and inc["appeal"]["status"] == "open"
        mask = appeal_open and not (as_role and self.config.appeal_can_view_sensitive(as_role))

        evidence = [{
            "evidence_id": e["evidence_id"], "kind": e["kind"],
            "content_ref": "【申诉期间已限制查看】" if mask else e["content_ref"],
            "content_sha256": e["content_sha256"], "state": e["state"],
            "submitted_by": e["submitted_by"], "at": e["at"], "note": e["note"],
        } for e in inc["evidence"]]

        accounts = [{
            "platform": "【申诉期间已限制】" if mask else a["platform"],
            "account_key": "【申诉期间已限制】" if mask else a["account_key"],
            "url": "【申诉期间已限制】" if mask else a.get("url"),
            "display_name": "【申诉期间已限制】" if mask else a.get("display_name"),
            "renamed": len(a["name_history"]) > 1,
            "name_history": [] if mask else a["name_history"],
        } for a in inc["accounts"]]

        actions = [self._action_view(a, inc) for a in inc["actions"]]
        # 冻结（申诉中/待解冻）与已取消（申诉成立）均不在可执行待办之列；
        # blocked 为已批准但授权不足的派生展示。
        pending = [a["action_id"] for a in actions if a["status"] in ("pending", "approved", "blocked")]
        frozen = [a["action_id"] for a in actions if a["status"] == "frozen"]
        cancelled = [a["action_id"] for a in actions if a["status"] == "cancelled"]

        digest = {
            "incident_id": inc["incident_id"],
            "status": self._status_of(inc),
            "victim_code": inc["victim_code"],
            "platform": inc["platform"],
            "severity": self.config.severities[inc["severity"]],
            "report_nos": inc["report_nos"],
            "opened_at": inc["opened_at"],
            "merged_into": inc.get("merged_into"),
            "absorbed_incidents": inc.get("absorbed", []),
            "证据依据": {
                "evidence": evidence,
                "linked_accounts": accounts,
                "platform_receipts": inc["receipts"],
            },
            "处置决定": actions,
            "当事人当前授权范围": [
                {"code": s, "name": self.config.scopes[s]["名称"]}
                for s in inc["consent_scopes"]
            ],
            "尚未完成的保护动作": {
                "action_ids": pending,
                "frozen_action_ids": frozen,
                "cancelled_action_ids": cancelled,
                "open_escalation": bool(inc["escalation"] and inc["escalation"]["status"] == "open"),
            },
            "值班升级": inc["escalation"],
            "申诉": inc["appeal"],
            "责任链": self._timeline(inc, mask),
        }
        if inc.get("closed_at"):
            digest["closed_at"] = inc["closed_at"]
            digest["close_reason"] = inc["close_reason"]
        return digest

    def _action_view(self, action_id, inc):
        a = self.actions[action_id]
        view = {
            "action_id": a["action_id"], "action_type": a["action_type"],
            "name": self.config.actions[a["action_type"]]["名称"],
            "status": a["status"], "proposed_by": a["proposed_by"],
            "proposed_by_role": a["proposed_by_role"],
            "required_reviewer_role": a["required_reviewer_role"],
            "reviewer": a["reviewer"], "review_reason": a["review_reason"],
            "executed_at": a["executed_at"], "result": a["result"],
        }
        # 冻结态：显式 frozen，并保留冻结前状态与原审批/复核依据，
        # 说明该动作为何不能手工执行、依据是什么。
        if a["status"] == "frozen":
            view["frozen"] = {
                "at": a["frozen_at"], "by": a["frozen_by"],
                "reason": a["frozen_reason"],
                "from_status": a["frozen_from_status"],
                "reviewer": a["reviewer"],
                "review_reason": a["review_reason"],
            }
            missing = [s for s in a["required_scopes"] if s not in inc["consent_scopes"]]
            if missing:
                view["blocked_reason"] = "授权已撤回：" + "、".join(
                    self.config.scopes[s]["名称"] for s in missing)
        elif a["status"] == "cancelled":
            view["cancelled"] = {
                "at": a["cancelled_at"], "by": a["cancelled_by"],
                "reason": a["cancel_reason"],
            }
        elif a["status"] == "approved":
            missing = [s for s in a["required_scopes"] if s not in inc["consent_scopes"]]
            if missing:
                view["status"] = "blocked"
                view["blocked_reason"] = "授权已撤回：" + "、".join(
                    self.config.scopes[s]["名称"] for s in missing)
        return view

    def _timeline(self, inc, mask):
        wanted = set(inc["report_nos"])
        incident_ids = {inc["incident_id"]}
        for absorbed_id in inc.get("absorbed", []):
            absorbed = self.incidents.get(absorbed_id)
            if absorbed:
                incident_ids.add(absorbed_id)
                wanted.update(absorbed["report_nos"])
        chain = []
        for event in self.store.replay():
            p = event["payload"]
            if p.get("incident_id") in incident_ids or p.get("report_no") in wanted:
                # 拷贝后再脱敏，绝不在账本原始事件上改写（账本只追加、不可变）。
                chain.append({"seq": event["seq"], "type": event["type"],
                              "payload": copy.deepcopy(p)})
        if mask:
            for item in chain:
                p = item["payload"]
                for field in ("content_ref", "content_url", "raw_excerpt", "url", "display_name"):
                    if field in p and p[field]:
                        p[field] = "【申诉期间已限制】"
                if "linked_accounts" in p:
                    p["linked_accounts"] = ["【申诉期间已限制】" for _ in p["linked_accounts"]]
        return chain

    @_transaction
    def list_incidents(self, status=None, severity=None):
        out = []
        for incident_id, inc in self.incidents.items():
            current = self._status_of(inc)
            if status and current != status:
                continue
            if severity and inc["severity"] != severity:
                continue
            out.append({
                "incident_id": incident_id, "status": current,
                "victim_code": inc["victim_code"], "severity": inc["severity"],
                "platform": inc["platform"], "opened_at": inc["opened_at"],
                "merged_into": inc.get("merged_into"),
                "open_escalation": bool(inc["escalation"] and inc["escalation"]["status"] == "open"),
            })
        return out

    @_transaction
    def list_suggestions(self, status="open"):
        return [dict(s) for s in self.suggestions.values() if status is None or s["status"] == status]

    @_transaction
    def list_reports(self):
        return list(self.reports.values())

    @_transaction
    def list_notifications(self, incident_id=None):
        if incident_id:
            return [n for n in self.notifications if n["incident_id"] == incident_id]
        return list(self.notifications)
