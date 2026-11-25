"""Pinned local ActionBase entry, with a pure check-mode fast path."""

from __future__ import annotations

from ansible.plugins.action import ActionBase

from netops.ansible import action_runtime


class NetopsWorkflowAction(ActionBase):
    """Execute only an inherited pending host invocation, never secret task vars."""

    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("handle",))

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Return minimized safe facts; check mode touches no private client."""
        if self._task.check_mode is True:
            return {"changed": False, "skipped": True, "netops": {"executed": False}}
        # Do not call ActionBase.run: no remote tmp directory, connection setup,
        # async staging or module execution is needed by a controller-local action.
        args = self._task.args
        if (
            not isinstance(args, dict) or set(args) != {"handle"}
            or not isinstance(args["handle"], str) or action_runtime._CLIENT is None
        ):
            return {"changed": False, "failed": True, "msg": "credential-scope-invalid"}
        try:
            # Ansible can tag its in-process templated strings/dictionaries.
            # Normalize only this nonsecret handle, never protocol authority.
            result = action_runtime._CLIENT.execute(str(args["handle"]))
            return {
                "changed": result["changed"], "failed": result["status"] != "succeeded",
                "netops": result,
            }
        except Exception:
            return {"changed": False, "failed": True, "msg": "control-lost"}


ActionModule = NetopsWorkflowAction
