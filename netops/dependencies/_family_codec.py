"""Closed decoding of retained lock facts, never of live source or grant objects."""

from __future__ import annotations

from dataclasses import fields

from netops.ansible import contracts as c

from ._assets import LockedAsset
from ._family_lock import _FamilyLock, _PublisherSnapshot, _Release, _Requirement, _Target
from ._managed import ManagedMember

__all__: tuple[str, ...] = ()
def _record(
    kind: type[_FamilyLock] | type[_PublisherSnapshot] | type[_Release]
    | type[_Requirement] | type[_Target] | type[ManagedMember] | type[LockedAsset],
    value: object,
) -> dict:
    data = dict(c.public_object(value))
    if set(data) != {field.name for field in fields(kind)}:
        raise c.ContractError()
    return data


def _sequence(value: object, maximum: int) -> tuple:
    if type(value) not in (tuple, list) or not isinstance(value, (tuple, list)):
        raise c.ContractError()
    if len(value) > maximum:
        raise c.ContractError()
    return tuple(value)


def _requirement(value: object) -> _Requirement:
    data = _record(_Requirement, value)
    data["extras"] = _sequence(data["extras"], 64)
    return _Requirement(**data)


def _target(value: object) -> _Target:
    data = _record(_Target, value)
    data["wheel_tags"] = _sequence(data["wheel_tags"], 1024)
    return _Target(**data)


def _release(value: object) -> _Release:
    data = _record(_Release, value)
    data["requirement"] = _requirement(data["requirement"])
    for key in ("platforms", "architectures", "abis", "wheel_tags", "scopes"):
        data[key] = _sequence(data[key], 1024)
    data["requires"] = tuple(_requirement(item) for item in _sequence(data["requires"], 256))
    data["members"] = tuple(
        ManagedMember(**_record(ManagedMember, item))
        for item in _sequence(data["members"], 4096)
    )
    extras = []
    for pair in _sequence(data["extra_requires"], 64):
        pair = _sequence(pair, 2)
        if len(pair) != 2:
            raise c.ContractError()
        extras.append((pair[0], tuple(_requirement(item) for item in _sequence(pair[1], 256))))
    data["extra_requires"] = tuple(extras)
    if data["artifact"] is not None:
        data["artifact"] = LockedAsset(**_record(LockedAsset, data["artifact"]))
    return _Release(**data)


def _decode_lock(value: object) -> _FamilyLock:
    """Revalidate every retained fact; no wire key selects executable behavior."""
    data = _record(_FamilyLock, value)
    data["roots"] = tuple(_requirement(item) for item in _sequence(data["roots"], 256))
    data["targets"] = tuple(_target(item) for item in _sequence(data["targets"], 2))
    data["releases"] = tuple(_release(item) for item in _sequence(data["releases"], 256))
    observations = []
    for item in _sequence(data["observations"], 256):
        snapshot = _record(_PublisherSnapshot, item)
        snapshot["releases"] = tuple(
            _release(release) for release in _sequence(snapshot["releases"], 1024)
        )
        observations.append(_PublisherSnapshot(**snapshot))
    data["observations"] = tuple(observations)
    extras = []
    for pair in _sequence(data["selected_extras"], 256):
        pair = _sequence(pair, 2)
        if len(pair) != 2:
            raise c.ContractError()
        extras.append((_sequence(pair[0], 3), _sequence(pair[1], 64)))
    data["selected_extras"] = tuple(extras)
    return _FamilyLock(**data)
