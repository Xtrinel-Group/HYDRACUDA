"""Adapter type registry.

Maps the `type` field of a policy file's `adapters:` entry to a factory, so
`validate` and `plan` can build the declared surface from the policy alone.
"""

from collections.abc import Callable

from hydracuda.adapters import Adapter, AdapterError
from hydracuda.adapters.local_tools import LocalToolsAdapter
from hydracuda.policy import AdapterSpec

AdapterFactory = Callable[[AdapterSpec], Adapter]

_FACTORIES: dict[str, AdapterFactory] = {}

_LOCAL_TOOLS_CONFIG = {"root", "reject_encoded_paths", "resolve_symlinks"}


def register_adapter_type(type_name: str, factory: AdapterFactory) -> None:
    """Register a factory for an adapter `type`."""
    _FACTORIES[type_name] = factory


def adapter_types() -> list[str]:
    """Every registered adapter type name."""
    return sorted(_FACTORIES)


def build_adapter(spec: AdapterSpec) -> Adapter:
    """Build an adapter from a policy file declaration.

    The resulting adapter declares the resource surface but has no handlers —
    those live in the integrator's process. It can be planned against; it
    cannot execute.
    """
    factory = _FACTORIES.get(spec.type)
    if factory is None:
        raise AdapterError(
            f"adapter '{spec.name}': unknown type '{spec.type}' — "
            f"registered types: {adapter_types()}"
        )
    return factory(spec)


def _build_local_tools(spec: AdapterSpec) -> LocalToolsAdapter:
    unknown = sorted(set(spec.config) - _LOCAL_TOOLS_CONFIG)
    if unknown:
        raise AdapterError(
            f"adapter '{spec.name}': unrecognized config key(s) {unknown} — "
            f"allowed: {sorted(_LOCAL_TOOLS_CONFIG)}"
        )

    adapter = LocalToolsAdapter(
        spec.name,
        root=spec.config.get("root"),
        reject_encoded_paths=spec.config.get("reject_encoded_paths", True),
        resolve_symlinks=spec.config.get("resolve_symlinks", True),
    )
    for resource in spec.resources:
        adapter.declare(resource)
    return adapter


register_adapter_type("local_tools", _build_local_tools)
