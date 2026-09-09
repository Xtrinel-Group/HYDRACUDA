"""The `local_tools` adapter — local Python callables as gated resources.

This is what HYDRACUDA instrumented before Phase 1: a dict of tool names to
async handlers, passed into `ToolCallProxy.call()` one at a time. Collecting
them behind the `Adapter` interface makes the resource surface declarable, so
`plan` can enumerate it and `validate` can check the policy against it.
"""

import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from hydracuda.adapters import (
    Adapter,
    AdapterError,
    NormalizedAction,
    ResourceSpec,
    UndeclaredResource,
)
from hydracuda.canonical import canonicalize_path


class LocalToolsAdapter(Adapter):
    """Exposes local callables under declared resource names.

    `root` confines every declared path parameter: a value resolving outside it
    is refused before any rule is evaluated. Set it whenever the tools touch
    the filesystem — without it, canonicalization still resolves `..` and
    symlinks, but nothing bounds where the result may land.
    """

    def __init__(
        self,
        name: str = "local",
        *,
        root: str | None = None,
        reject_encoded_paths: bool = True,
        resolve_symlinks: bool = True,
    ):
        self._name = name
        self._root = root
        self._reject_encoded_paths = reject_encoded_paths
        self._resolve_symlinks = resolve_symlinks
        self._specs: dict[str, ResourceSpec] = {}
        self._handlers: dict[str, Callable[..., Any]] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def root(self) -> str | None:
        return self._root

    def resource_specs(self) -> Sequence[ResourceSpec]:
        return tuple(self._specs.values())

    def register(
        self,
        resource: str,
        handler: Callable[..., Any] | None = None,
        *,
        description: str = "",
        parameters: Sequence[str] = (),
        path_parameters: Sequence[str] = (),
    ):
        """Declare a resource and the callable that performs it.

        Usable directly or as a decorator. `path_parameters` must name every
        parameter carrying a filesystem path; those are the ones canonicalized
        and confined by `normalize()`.
        """
        if resource in self._specs:
            raise AdapterError(
                f"adapter '{self._name}' already declares resource '{resource}'"
            )

        unknown = sorted(set(path_parameters) - set(parameters))
        if parameters and unknown:
            raise AdapterError(
                f"resource '{resource}': path_parameters {unknown} are not listed "
                f"in parameters {sorted(parameters)}"
            )

        spec = ResourceSpec(
            name=resource,
            description=description,
            parameters=tuple(parameters),
            path_parameters=tuple(path_parameters),
        )

        def _register(func: Callable[..., Any]) -> Callable[..., Any]:
            self._specs[resource] = spec
            self._handlers[resource] = func
            return func

        if handler is None:
            return _register
        return _register(handler)

    def declare(
        self,
        resource: str,
        *,
        description: str = "",
        parameters: Sequence[str] = (),
        path_parameters: Sequence[str] = (),
    ) -> None:
        """Declare a resource with no handler.

        Used when building an adapter from a policy file's `adapters:` block:
        the resource surface is known, but the callables live in the
        integrator's process. Such a resource can be planned but not executed.
        """
        if resource in self._specs:
            raise AdapterError(
                f"adapter '{self._name}' already declares resource '{resource}'"
            )
        self._specs[resource] = ResourceSpec(
            name=resource,
            description=description,
            parameters=tuple(parameters),
            path_parameters=tuple(path_parameters),
        )

    def normalize(self, resource: str, params: Mapping[str, Any]) -> NormalizedAction:
        """Canonicalize declared path parameters before evaluation.

        Raises CanonicalizationError for a path that cannot be resolved safely
        or that escapes `root`. The caller treats that as a denial, so a
        traversal attempt is refused whether or not any deny pattern describes
        its particular spelling.
        """
        spec = self.spec_for(resource)
        if spec is None:
            raise UndeclaredResource(
                f"adapter '{self._name}' does not declare resource '{resource}'"
            )

        resolved = dict(params)
        notes: list[str] = []

        for param in spec.path_parameters:
            if param not in resolved:
                continue
            original = resolved[param]
            canonical = canonicalize_path(
                original,
                root=self._root,
                reject_encoded=self._reject_encoded_paths,
                resolve_symlinks=self._resolve_symlinks,
            )
            if canonical.value != original:
                notes.append(f"{param}: {original!r} -> {canonical.value!r}")
            notes.extend(f"{param}: {note}" for note in canonical.notes)
            resolved[param] = canonical.value

        return NormalizedAction(resource=resource, params=resolved, notes=notes)

    async def execute(self, resource: str, params: Mapping[str, Any]) -> Any:
        handler = self._handlers.get(resource)
        if handler is None:
            if resource in self._specs:
                raise AdapterError(
                    f"resource '{resource}' is declared by adapter '{self._name}' "
                    f"but has no handler registered"
                )
            raise UndeclaredResource(
                f"adapter '{self._name}' does not declare resource '{resource}'"
            )

        result = handler(resource, dict(params))
        if inspect.isawaitable(result):
            return await result
        return result
