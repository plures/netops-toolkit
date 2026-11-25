"""Full nonempty lifecycle plan wire goldens, not a platform qualification."""

from netops.ansible import contracts as c
from netops.ansible.policy import contracts as lc
from netops.dependencies.service import InstallPlan, InstallStep

D = "1" * 64
PLAN = "10000000-0000-4000-8000-000000000001"
LIFE = "20000000-0000-4000-8000-000000000002"
GEN = "30000000-0000-4000-8000-000000000003"
PIN = "6d367fe673756dabaa6085bc6b5202debaaabe6f"

# Hand-authored contract bytes. Tokens stand only for fixed declared scalar
# values, never serialized implementation values or computed wire hashes.
EXPECTED_CONTEXT = (
    '{"context":{"assets_digest":"@D@","controller_id":"native-fixture",'
    '"mapping_digest":"@D@","policy_identity":@POLICY@,"registry_digest":"@D@",'
    '"route_digest":"@D@","source_id":"native-fixture"}}'
)
EXPECTED_POLICY = (
    '{"bundle_sha256":"@D@","canonical_revision":"6d367fe673756dabaa6085bc6b5202debaaabe6f",'
    '"contracts_sha256":"@D@","numeric_profile":"exact-int53-finite-order-v1",'
    '"profile":"netops-reference-v1","reducer_version":"1","rule_manifest":["fixture.rule"],'
    '"schema":"1.0","source_sha256":"@D@"}'
)
EXPECTED_SCOPE = (
    '{"companions":[],"enhanced":false,"full_toolkit":false,'
    '"native_capabilities":["native.stdlib"]}'
)
EXPECTED_LIFECYCLE = (
    '{"content":{"steps":[{"dependency":"toolkit-wheel-bundle","source":'
    '{"artifact_digest":"@D@","descriptor_digest":"@D@","registry_digest":"@D@",'
    '"source_id":"owned-local-build"}}]},'
    '"context_digest":"@D@","effects":[{"arguments_digest":"@D@",'
    '"kind":"dependency-download","occurrence_id":"download-0","ordinal":0,'
    '"resource_id":"owned-source","step_id":"acquire-current"}],'
    '"expected_pointer":{"kind":"absent","revision":0},'
    '"generation":{"content_digest":"@D@",'
    '"generation_id":"30000000-0000-4000-8000-000000000003",'
    '"manifest_digest":"@D@","ordinal":1,"selected":[]},'
    '"kind":"install","lifecycle_id":"20000000-0000-4000-8000-000000000002",'
    '"plan_digest":"@D@","plan_id":"10000000-0000-4000-8000-000000000001",'
    '"policy":@POLICY@,"qualification_digest":"@D@","registry_digest":"@D@",'
    '"required_consequential":[],"root":{"manifest_digest":"@D@",'
    '"resource_id":"owned-root"},"schema":"1.0","scope":@SCOPE@}'
)
EXPECTED_PUBLIC_PLAN = (
    '{"blocked":[],"consuming_contexts":["@D@"],"context":@CONTEXT@,'
    '"digest":"@D@","free_space":null,"id":"10000000-0000-4000-8000-000000000001",'
    '"lifecycle":@LIFECYCLE@,"policy_identity":@POLICY@,'
    '"qualification":"not-qualified","registry_digest":"@D@","registry_revision":"fixture-v1",'
    '"steps":[{"context":"native","dependency":"toolkit-wheel-bundle",'
    '"destination":"owned-generation","digest":"@D@","disposition":"acquire",'
    '"effects":["dependency-download","dependency-stage","dependency-verify"],'
    '"ownership":"user-local","reason":"fresh-owned-build","recovery":"preserve-current",'
    '"reuse":"not-observed","separate_grants":[],"size":128,'
    '"source":"owned-local-build"}]}'
)


def expected(template):
    """Expand only hand-declared literal scalar/composite contract constants."""
    for token, value in (
        ("@CONTEXT@", EXPECTED_CONTEXT), ("@LIFECYCLE@", EXPECTED_LIFECYCLE),
        ("@POLICY@", EXPECTED_POLICY), ("@SCOPE@", EXPECTED_SCOPE), ("@D@", D),
    ):
        template = template.replace(token, value)
    assert "@" not in template
    return template.encode("utf-8")


def values():
    """Construct explicit stable DTO inputs independently of product execution."""
    identity = lc.PolicyIdentity(PIN, D, D, D, ("fixture.rule",), "1")
    context = c.InstallContext(c.Context(
        "native-fixture", D, "native-fixture", D, identity, D, D,
    ))
    scope = c.InstallScope(("native.stdlib",), (), False, False)
    lifecycle = lc.InstallPlan(
        "1.0", PLAN, LIFE, D, D, lc.OwnedRootBinding("owned-root", D),
        lc.GenerationBinding(GEN, 1, D, D), lc.AbsentPointer("absent", 0), identity,
        D, D, (lc.LifecycleEffectOccurrence(
            "download-0", 0, "acquire-current", "owned-source", "dependency-download", D,
        ),), (), lc.object_value({"steps": ({
            "dependency": "toolkit-wheel-bundle", "source": {
                "source_id": "owned-local-build", "artifact_digest": D,
                "registry_digest": D, "descriptor_digest": D,
            },
        },)}), "install", scope,
    )
    step = InstallStep(
        "toolkit-wheel-bundle", "native", "user-local", "owned-local-build", D, 128,
        "owned-generation", "not-observed",
        ("dependency-download", "dependency-stage", "dependency-verify"), (),
        "preserve-current", "acquire", "fresh-owned-build",
    )
    return context, scope, lifecycle, InstallPlan(
        PLAN, D, context, "fixture-v1", D, (D,), identity, (step,), "not-qualified",
        lifecycle=lifecycle,
    )


def test_ac002_ac003_complete_install_request_literal_context_and_scope():
    context, scope, _, _ = values()
    assert c.canonical_bytes(context) == expected(EXPECTED_CONTEXT)
    assert c.canonical_bytes(scope) == expected(EXPECTED_SCOPE)


def test_ac002_ac003_nonempty_lifecycle_and_public_plan_literal_response():
    _, _, lifecycle, plan = values()
    assert c.canonical_bytes(lifecycle) == expected(EXPECTED_LIFECYCLE)
    assert c.canonical_bytes(plan) == expected(EXPECTED_PUBLIC_PLAN)
    assert len(plan.steps) == len(plan.lifecycle.effects) == 1
    # Safe serializable facts deliberately contain no private live authority.
    assert b"_issuer" not in c.canonical_bytes(plan)
