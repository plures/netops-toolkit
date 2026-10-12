"""CDCC M1 physical path/shared-risk evidence validator (stdlib-only EVT0).

This is a feasibility-analysis tool, NOT a construction authorization or
an availability prediction. It deliberately fails closed on incomplete facts.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = "cdcc.m1.srlg.v0.1"
EVIDENCE = {"verified", "estimated", "unknown"}
PROTECTION_SCOPES = {"upstream", "shared"}


def validate(data: dict[str, Any]) -> list[str]:
    errors = []
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must equal {SCHEMA}")
    if data.get("data_class") not in {"synthetic", "desk", "field_verified"}:
        errors.append("data_class must be synthetic/desk/field_verified")
    asset_items = data.get("assets")
    services = data.get("services")
    if not isinstance(asset_items, list) or not isinstance(services, list):
        return errors + ["assets and services must be arrays"]
    assets = {}
    for i, a in enumerate(asset_items):
        if not isinstance(a, dict) or not isinstance(a.get("id"), str):
            errors.append(f"assets[{i}] must have string id")
            continue
        ident = a["id"]
        if ident in assets:
            errors.append(f"duplicate asset id {ident}")
        assets[ident] = a
        if a.get("scope") not in PROTECTION_SCOPES:
            errors.append(f"{ident}: invalid scope")
        if a.get("evidence") not in EVIDENCE:
            errors.append(f"{ident}: invalid evidence")
        if not isinstance(a.get("srlgs"), list) or any(not isinstance(g, str) or not g for g in a.get("srlgs", [])):
            errors.append(f"{ident}: srlgs must be string array")
        if a.get("evidence") == "verified" and not a.get("source_ref"):
            errors.append(f"{ident}: verified evidence requires source_ref")
        if a.get("production_role") and a.get("site") == "townhouse":
            errors.append(f"{ident}: townhouse cannot host shared production equipment")
    service_ids = set()
    for i, s in enumerate(services):
        if not isinstance(s, dict) or not isinstance(s.get("id"), str):
            errors.append(f"services[{i}] must have string id")
            continue
        sid = s["id"]
        if sid in service_ids:
            errors.append(f"duplicate service id {sid}")
        service_ids.add(sid)
        if not isinstance(s.get("paths"), list) or len(s["paths"]) < 1:
            errors.append(f"{sid}: requires at least one path")
            continue
        for p in s["paths"]:
            if not isinstance(p, list) or not p:
                errors.append(f"{sid}: every path must be a nonempty asset-id list")
                continue
            for aid in p:
                if aid not in assets:
                    errors.append(f"{sid}: unknown asset {aid}")
    return errors


def assess_diversity(s: dict, assets: dict[str, dict]) -> dict:
    """Assess TWO protected upstream legs; not end-to-end diversity.

    A Type-B passive splitter/drop legitimately lies on both complete service
    paths and MUST still participate in failure injection/blast-radius tests.
    """
    paths = s["paths"]
    if len(paths) != 2:
        return {"status": "NOT_DUAL_PATH", "shared_upstream_assets": [], "shared_upstream_srlgs": [], "unverified_assets": []}
    upstream = [set(aid for aid in p if assets[aid]["scope"] == "upstream") for p in paths]
    upstream_groups = [{g for aid in leg for g in assets[aid]["srlgs"]} for leg in upstream]
    shared_assets = sorted(upstream[0] & upstream[1])
    shared_srlgs = sorted(upstream_groups[0] & upstream_groups[1])
    unverified = sorted(aid for aid in upstream[0] | upstream[1] if assets[aid]["evidence"] != "verified" or not assets[aid]["srlgs"])
    # Empty upstream leg is invalid as a protection claim.
    if not upstream[0] or not upstream[1]:
        status = "NOT_DUAL_PATH"
    elif shared_assets or shared_srlgs:
        status = "NOT_DIVERSE"
    elif unverified:
        status = "UNVERIFIED"
    else:
        status = "DIVERSE_IN_MODEL"
    common_downstream = sorted(set(paths[0]) & set(paths[1]) - (upstream[0] | upstream[1]))
    return {
        "status": status,
        "shared_upstream_assets": shared_assets,
        "shared_upstream_srlgs": shared_srlgs,
        "unverified_assets": unverified,
        "common_downstream_assets": common_downstream,
    }


def impact(services: list[dict], failed: set[str]) -> list[str]:
    """A subscriber is down iff all of its physical end-to-end paths fail."""
    return sorted(s["id"] for s in services if all(set(path) & failed for path in s["paths"]))


def report(data: dict) -> dict:
    errors = validate(data)
    if errors:
        return {"schema": SCHEMA, "valid": False, "errors": errors, "m1_reliability_credit": False}
    assets = {a["id"]: a for a in data["assets"]}
    all_services = data["services"]
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for s in all_services:
        by_domain[s.get("domain", "unassigned")].append(s)
    domains = {}
    for domain, services in sorted(by_domain.items()):
        assessments = [assess_diversity(s, assets) for s in services]
        domains[domain] = {
            "services": len(services),
            "protected_feeder_statuses": dict(sorted((k, sum(a["status"] == k for a in assessments)) for k in set(a["status"] for a in assessments))),
            "upstream_common_srlgs": sorted({x for a in assessments for x in a["shared_upstream_srlgs"]}),
            "upstream_common_assets": sorted({x for a in assessments for x in a["shared_upstream_assets"]}),
            "unknown_evidence": sorted({x for a in assessments for x in a["unverified_assets"]}),
            "common_downstream_assets": sorted({x for a in assessments for x in a["common_downstream_assets"]}),
        }
    failure_rows = []
    for aid in sorted(assets):
        impacted = impact(all_services, {aid})
        if impacted:
            failure_rows.append({"failure": f"asset:{aid}", "outages": len(impacted)})
    memberships: dict[str, set[str]] = defaultdict(set)
    for aid, asset in assets.items():
        for srlg in asset["srlgs"]:
            memberships[srlg].add(aid)
    for name in sorted(memberships):
        impacted = impact(all_services, memberships[name])
        if impacted:
            failure_rows.append({"failure": f"srlg:{name}", "outages": len(impacted)})
    failure_rows.sort(key=lambda x: (-x["outages"], x["failure"]))
    all_protected = all(
        all(assess_diversity(s, assets)["status"] == "DIVERSE_IN_MODEL" for s in services)
        for services in by_domain.values()
    )
    all_assets_verified = all(a["evidence"] == "verified" for a in assets.values())
    field_evidence = (
        data["data_class"] == "field_verified" and all_assets_verified
        and all(a.get("source_ref") and "SYNTHETIC" not in a["source_ref"].upper()
                and a.get("srlgs") for a in assets.values())
    )
    # This is only an evidence precondition, never a construction approval.
    return {
        "schema": SCHEMA, "valid": True, "data_class": data["data_class"],
        "subscriber_services": len(all_services),
        "domains": domains,
        "max_single_failure_blast_radius": max((x["outages"] for x in failure_rows), default=0),
        "nonzero_failure_scenarios": failure_rows,
        "field_evidence_complete": field_evidence,
        "feeder_diversity_in_model": all_protected,
        "eligible_for_m1_review": bool(field_evidence and all_protected),
        "m1_reliability_credit": False,  # human/organizational M1 approval is never automated
        "warning": "No automated construction approval. Synthetic/desk data is not field evidence. Feeder diversity does not protect shared splitters/drops. Explicit M1 decision review is mandatory."
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    result = report(json.loads(args.input.read_text()))
    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(serialized + "\n")
    else:
        print(serialized)
    if not result["valid"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
