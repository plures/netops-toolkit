"""Declarative prerequisite registry and read-only consuming-context readiness."""

from .adapters import LocalDependencyAdapter
from .service import (
    ConsumingContext,
    DependencyAdapter,
    DependencyCatalog,
    DependencyEntry,
    DependencyRegistry,
    DependencyService,
    InstallPlan,
    InstallStep,
    OwnedStatePort,
    ProbeResult,
    PublicOperation,
    RegistryError,
)

__all__ = [
    "ConsumingContext", "DependencyAdapter", "DependencyCatalog", "DependencyEntry",
    "DependencyRegistry", "DependencyService", "InstallPlan", "InstallStep",
    "LocalDependencyAdapter", "OwnedStatePort", "ProbeResult", "PublicOperation", "RegistryError",
]
