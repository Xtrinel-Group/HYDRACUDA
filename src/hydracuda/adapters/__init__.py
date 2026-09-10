"""Adapter interface for HYDRACUDA.

An adapter answers "what exists" — the resources and actions an integration
exposes. Policy answers "what is permitted". The two are connected only by the
resource vocabulary the adapter declares, so the engine never needs to know
what an adapter does internally.

An adapter has one security responsibility the engine cannot take on:
`normalize()` turns a caller-supplied request into its canonical form before
any rule is evaluated, and the canonical form is what gets executed. See
`hydracuda.canonical`.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


class AdapterError(Exception):
    """Base class for adapter failures."""


class UndeclaredResource(AdapterError):
    """Raised when a request names a resource the adapter does not declare.

    Distinct from a policy denial: the resource does not exist as far as this
    adapter is concerned, so no rule — however broad — should reach it.
    """


@dataclass(frozen=True)
class ResourceSpec:
    """One resource an adapter exposes.

    `path_parameters` names the parameters holding filesystem paths. Declaring
    them is what causes them to be canonicalized and confined before
    evaluation, so an omission here is a security-relevant omission.
    """

    name: str
    description: str = ""
    parameters: tuple[str, ...] = ()
    path_parameters: tuple[str, ...] = ()


@dataclass
class NormalizedAction:
    """A request after canonicalization, ready to be evaluated and executed."""

    resource: str
    params: dict[str, Any]
    notes: list[str] = field(default_factory=list)


class Adapter(ABC):
    """Declares a resource surface, independent of how policy evaluates it."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique instance name, used in diagnostics and audit records."""

    @abstractmethod
    def resource_specs(self) -> Sequence[ResourceSpec]:
        """Every resource this adapter exposes."""

    def resources(self) -> list[str]:
        """Declared resource names, in declaration order."""
        return [spec.name for spec in self.resource_specs()]

    def spec_for(self, resource: str) -> ResourceSpec | None:
        """The spec for a resource, or None when it is not declared."""
        for spec in self.resource_specs():
            if spec.name == resource:
                return spec
        return None

    def declares(self, resource: str) -> bool:
        """True when this adapter exposes `resource`."""
        return self.spec_for(resource) is not None

    def normalize(self, resource: str, params: Mapping[str, Any]) -> NormalizedAction:
        """Canonicalize a request before it is evaluated.

        The default implementation is the identity transform. Override it
        whenever a parameter has a canonical form that differs from its
        spelling — paths, URLs, identifiers with optional prefixes — and raise
        `hydracuda.canonical.CanonicalizationError` for input that cannot be
        canonicalized safely. Callers treat that as a denial.
        """
        if not self.declares(resource):
            raise UndeclaredResource(
                f"adapter '{self.name}' does not declare resource '{resource}'"
            )
        return NormalizedAction(resource=resource, params=dict(params))

    async def execute(self, resource: str, params: Mapping[str, Any]) -> Any:
        """Perform the action. Only reached once policy has allowed it."""
        raise NotImplementedError(
            f"adapter '{self.name}' does not implement execute()"
        )


__all__ = [
    "Adapter",
    "AdapterError",
    "NormalizedAction",
    "ResourceSpec",
    "UndeclaredResource",
]
