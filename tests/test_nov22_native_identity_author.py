"""Additional author device-identity and native grammar omission controls."""

from dataclasses import replace

import pytest

from netops.ansible import contracts as c
from netops.ansible import workflows as w
from tests.test_c01_independent_nov17 import environment as environment
from tests.test_c01_independent_nov17 import hydrated, input_source, request


def test_selected_device_identity_guard_rejects_foreign_observation(environment):
    _, context, _ = environment
    source = input_source("before", content=b"hostname r1\n")
    req = replace(request(context, "compare.compare"), inputs=(source.source,))
    item = c.LoadedInput(source.source, source.format, source.content,
                         source.parser_revision, source.vendor_revision)
    observation = c.Observation(
        "native-reading", "unselected-device", c.digest(context), context.route_digest,
        context.controller_id, source.source, source.source.digest, "2026-11-21T00:00:00Z", 0.0,
    )
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        w._observations(req, (item,), (observation,))


def test_versioned_native_provenance_does_not_skip_nonconfiguration_grammar(
    environment, monkeypatch,
):
    service, context, _ = environment
    sources = tuple(replace(
        input_source(kind, content=data),
        parser_revision="collector-parser-v2", vendor_revision="collector-vendor-v2",
    ) for kind, data in (("before", b"<script>unsafe</script>\n"),
                        ("after", b"hostname r1\n")))
    req, loaded = hydrated(request(context, "compare.compare"), *sources)
    monkeypatch.setattr(w, "diff_configs", lambda *a, **kw: pytest.fail("native parser entered"))
    with pytest.raises(c.ContractError, match="input-binding-invalid"):
        service.preview(req, loaded)
