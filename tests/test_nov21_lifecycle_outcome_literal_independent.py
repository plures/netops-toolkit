"""Nonempty lifecycle output contract pins, including failure and uncertainty."""

from netops.ansible import contracts as c
from netops.dependencies._lifecycle import InstallOutcome, InstallStepOutcome
from tests.test_nov21_lifecycle_literal_independent import GEN, LIFE, PLAN

ERROR = (
    '{"category":"dependency","detail":"","next_action":"Replan and review.",'
    '"reason":"provision-failed","retryable":false,"stage":"provision",'
    '"step_id":"verify-current","target_id":null}'
)
SCOPE = (
    '{"companions":[],"enhanced":false,"full_toolkit":false,'
    '"native_capabilities":["native.stdlib"]}'
)
EXPECTED_PARTIAL = (
    '{"active_generation_id":null,"candidate_generation_id":"@GEN@",'
    '"cleanup_errors":[],"errors":[@ERROR@],"installation_id":"@LIFE@",'
    '"kind":"install","original_errors":[@ERROR@],'
    '"pending_actions":["review-activation-plan"],"plan_id":"@PLAN@",'
    '"pointer_revision":0,"previous_generation_id":null,'
    '"readiness":{"companion":"not-requested","enhanced":"not-requested",'
    '"errors":[],"native":"blocked"},"remote_state":"not-requested",'
    '"schema_version":"1.0","selected_scope":@SCOPE@,"status":"partial",'
    '"steps":[{"changed":true,"error":null,"kind":"dependency-stage",'
    '"occurrence_id":"stage-0","status":"succeeded","step_id":"stage-current"},'
    '{"changed":false,"error":@ERROR@,"kind":"dependency-verify",'
    '"occurrence_id":"verify-1","status":"failed","step_id":"verify-current"}],'
    '"uncertain":true}'
)
EXPECTED_ACTIVATED = (
    '{"active_generation_id":"@GEN@","candidate_generation_id":"@GEN@",'
    '"cleanup_errors":[],"errors":[],"installation_id":"@LIFE@",'
    '"kind":"install","original_errors":[],"pending_actions":[],"plan_id":"@PLAN@",'
    '"pointer_revision":1,"previous_generation_id":null,'
    '"readiness":{"companion":"not-requested","enhanced":"not-requested",'
    '"errors":[],"native":"ready"},"remote_state":"not-requested",'
    '"schema_version":"1.0","selected_scope":@SCOPE@,"status":"succeeded",'
    '"steps":[{"changed":true,"error":null,"kind":"dependency-activate",'
    '"occurrence_id":"activate-0","status":"succeeded","step_id":"activate-current"}],'
    '"uncertain":false}'
)


def expected(template):
    """Expand only fixed hand-authored contract literals, never product wire."""
    for token, value in (
        ("@GEN@", GEN), ("@LIFE@", LIFE), ("@PLAN@", PLAN),
        ("@ERROR@", ERROR), ("@SCOPE@", SCOPE),
    ):
        template = template.replace(token, value)
    assert "@" not in template
    return template.encode("utf-8")


def test_ac002_ac011_nonempty_partial_lifecycle_response_is_exact_literal():
    error = c.SafeError(
        c.ErrorCategory.DEPENDENCY, c.ReasonCode.PROVISION_FAILED, c.Stage.PROVISION,
        step_id="verify-current", next_action="Replan and review.",
    )
    result = InstallOutcome(
        LIFE, PLAN, "install", c.OutcomeStatus.PARTIAL,
        (InstallStepOutcome(
            "stage-0", "stage-current", "dependency-stage", c.OutcomeStatus.SUCCEEDED, True,
        ), InstallStepOutcome(
            "verify-1", "verify-current", "dependency-verify", c.OutcomeStatus.FAILED, error=error,
        )),
        c.ReadinessProjection("blocked", "not-requested", "not-requested"),
        GEN, None, None, errors=(error,), pending_actions=("review-activation-plan",),
        uncertain=True, pointer_revision=0,
        selected_scope=c.InstallScope(("native.stdlib",), (), False, False),
        original_errors=(error,),
    )
    assert c.canonical_bytes(result) == expected(EXPECTED_PARTIAL)


def test_ac002_ac011_nonempty_activated_lifecycle_response_is_exact_literal():
    result = InstallOutcome(
        LIFE, PLAN, "install", c.OutcomeStatus.SUCCEEDED,
        (InstallStepOutcome(
            "activate-0", "activate-current", "dependency-activate",
            c.OutcomeStatus.SUCCEEDED, True,
        ),),
        c.ReadinessProjection("ready", "not-requested", "not-requested"),
        GEN, GEN, None, pointer_revision=1,
        selected_scope=c.InstallScope(("native.stdlib",), (), False, False),
    )
    assert c.canonical_bytes(result) == expected(EXPECTED_ACTIVATED)
