"""Tests for the adapter interface and the local_tools adapter.

The contract being pinned here has three parts:

1. An adapter declares its resource surface; the engine evaluates against that
   vocabulary rather than hardcoded tool knowledge.
2. A resource no adapter declares is refused before any rule is consulted.
3. Normalization happens before evaluation, and the normalized parameters are
   the ones handed to the handler.
"""

import os

import pytest
import yaml

from hydracuda.adapters import (
    Adapter,
    AdapterError,
    NormalizedAction,
    ResourceSpec,
    UndeclaredResource,
)
from hydracuda.adapters.local_tools import LocalToolsAdapter
from hydracuda.adapters.registry import adapter_types, build_adapter
from hydracuda.engine import PolicyEngine
from hydracuda.policy import AdapterSpec, parse_policy
from hydracuda.proxy import ToolCallProxy


def _policy(text):
    return parse_policy(yaml.safe_load(text))


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "notes.txt").write_text("ok")
    return root


@pytest.fixture
def adapter(workspace):
    a = LocalToolsAdapter("local", root=workspace)
    a.register(
        "read_file",
        _echo,
        description="Read a file",
        parameters=("path",),
        path_parameters=("path",),
    )
    a.register("ping", _echo, description="No path arguments")
    return a


async def _echo(resource, params):
    return {"resource": resource, "params": params}


# --- interface contract --------------------------------------------------


def test_adapter_requires_name_and_resource_specs():
    class Incomplete(Adapter):
        pass

    with pytest.raises(TypeError):
        Incomplete()


def test_minimal_adapter_satisfies_the_interface():
    class Minimal(Adapter):
        name = "minimal"

        def resource_specs(self):
            return (ResourceSpec(name="thing.do"),)

    a = Minimal()
    assert a.resources() == ["thing.do"]
    assert a.declares("thing.do") is True
    assert a.declares("thing.undo") is False
    assert a.spec_for("thing.undo") is None


def test_default_normalize_is_the_identity_transform():
    class Minimal(Adapter):
        name = "minimal"

        def resource_specs(self):
            return (ResourceSpec(name="thing.do"),)

    action = Minimal().normalize("thing.do", {"x": 1})
    assert action == NormalizedAction(resource="thing.do", params={"x": 1}, notes=[])


def test_default_normalize_refuses_undeclared_resources():
    class Minimal(Adapter):
        name = "minimal"

        def resource_specs(self):
            return (ResourceSpec(name="thing.do"),)

    with pytest.raises(UndeclaredResource, match="does not declare"):
        Minimal().normalize("thing.undo", {})


async def test_execute_is_not_implemented_by_default():
    class Minimal(Adapter):
        name = "minimal"

        def resource_specs(self):
            return (ResourceSpec(name="thing.do"),)

    with pytest.raises(NotImplementedError):
        await Minimal().execute("thing.do", {})


def test_normalize_does_not_mutate_the_caller_params(adapter):
    params = {"path": "notes.txt"}
    adapter.normalize("read_file", params)
    assert params == {"path": "notes.txt"}


# --- declaration ---------------------------------------------------------


def test_resources_are_reported_in_declaration_order(adapter):
    assert adapter.resources() == ["read_file", "ping"]


def test_spec_records_parameters(adapter):
    spec = adapter.spec_for("read_file")
    assert spec.parameters == ("path",)
    assert spec.path_parameters == ("path",)
    assert spec.description == "Read a file"


def test_register_works_as_a_decorator(workspace):
    a = LocalToolsAdapter(root=workspace)

    @a.register("write_file", parameters=("path",), path_parameters=("path",))
    async def _write(resource, params):
        return params

    assert a.resources() == ["write_file"]


def test_duplicate_resource_is_an_error(adapter):
    with pytest.raises(AdapterError, match="already declares"):
        adapter.register("read_file", _echo)


def test_declare_duplicate_is_an_error(adapter):
    with pytest.raises(AdapterError, match="already declares"):
        adapter.declare("read_file")


def test_path_parameter_must_be_a_declared_parameter(workspace):
    # A typo here would silently skip canonicalization, so it is rejected.
    a = LocalToolsAdapter(root=workspace)
    with pytest.raises(AdapterError, match="not listed in parameters"):
        a.register("read_file", _echo, parameters=("path",), path_parameters=("paht",))


async def test_declared_resource_without_a_handler_cannot_execute(workspace):
    a = LocalToolsAdapter(root=workspace)
    a.declare("read_file")
    with pytest.raises(AdapterError, match="no handler registered"):
        await a.execute("read_file", {})


async def test_executing_an_undeclared_resource_is_refused(adapter):
    with pytest.raises(UndeclaredResource):
        await adapter.execute("rm_rf", {})


async def test_sync_handlers_are_supported(workspace):
    a = LocalToolsAdapter(root=workspace)
    a.register("ping", lambda resource, params: "pong")
    assert await a.execute("ping", {}) == "pong"


# --- normalization -------------------------------------------------------


def test_declared_path_parameters_are_canonicalized(adapter, workspace):
    action = adapter.normalize("read_file", {"path": "sub/../notes.txt"})
    assert action.params["path"] == os.path.realpath(str(workspace / "notes.txt"))
    assert action.notes


def test_traversal_is_refused_by_the_adapter(adapter):
    from hydracuda.canonical import CanonicalizationError

    with pytest.raises(CanonicalizationError):
        adapter.normalize("read_file", {"path": "../../etc/passwd"})


def test_undeclared_path_parameters_are_left_alone(adapter):
    # `ping` declares no path parameters, so nothing is resolved even though
    # the value looks like a path.
    action = adapter.normalize("ping", {"path": "../../etc/passwd"})
    assert action.params == {"path": "../../etc/passwd"}
    assert action.notes == []


def test_missing_path_parameter_is_not_invented(adapter):
    action = adapter.normalize("read_file", {})
    assert action.params == {}


# --- registry ------------------------------------------------------------


def test_local_tools_is_a_registered_type():
    assert "local_tools" in adapter_types()


def test_build_adapter_declares_the_policy_surface(workspace):
    spec = AdapterSpec(
        name="fs",
        type="local_tools",
        resources=["read_file", "write_file"],
        config={"root": str(workspace)},
    )
    built = build_adapter(spec)
    assert built.name == "fs"
    assert built.resources() == ["read_file", "write_file"]
    assert built.root == str(workspace)


def test_build_adapter_rejects_unknown_types():
    with pytest.raises(AdapterError, match="unknown type"):
        build_adapter(AdapterSpec(name="x", type="quantum_tunnel"))


def test_build_adapter_rejects_unknown_config_keys(workspace):
    with pytest.raises(AdapterError, match="unrecognized config key"):
        build_adapter(
            AdapterSpec(name="fs", type="local_tools", config={"rooot": "/tmp"})
        )


def test_policy_declared_adapters_can_be_built(examples_dir):
    policy = _policy((examples_dir / "policy.yaml").read_text())
    for spec in policy.adapters:
        built = build_adapter(spec)
        assert built.resources() == spec.resources


# --- proxy integration ---------------------------------------------------


POLICY = """
version: 2
default_action: deny
audit_path: "{audit}"
adapters:
  - name: local
    type: local_tools
    resources: [read_file, ping]
rules:
  - name: block-etc
    resource: read_file
    action: deny
    where:
      path:
        matches: ["/etc/", "\\\\.\\\\."]
  - name: allow-reads
    resource: read_file
    action: allow
  - name: allow-ping
    resource: ping
    action: allow
"""


@pytest.fixture
def proxy(tmp_path, adapter):
    policy = _policy(POLICY.format(audit=tmp_path / "audit.db"))
    return ToolCallProxy(PolicyEngine(policy), adapter=adapter)


async def test_proxy_executes_through_the_adapter(proxy, workspace):
    result = await proxy.call("read_file", {"path": "notes.txt"})
    assert result["params"]["path"] == os.path.realpath(str(workspace / "notes.txt"))


async def test_the_handler_receives_the_canonical_params(proxy, workspace):
    """The value that was checked is the value that runs.

    Canonicalizing for the decision and then executing the original string
    would make the check meaningless, so this is the load-bearing assertion of
    the whole adapter layer.
    """
    seen = {}

    async def handler(resource, params):
        seen.update(params)
        return "done"

    assert await proxy.call("read_file", {"path": "sub/../notes.txt"}, handler) == "done"
    assert seen["path"] == os.path.realpath(str(workspace / "notes.txt"))
    assert seen["path"] != "sub/../notes.txt"


async def test_symlink_escape_is_denied_though_no_pattern_describes_it(
    proxy, workspace
):
    (workspace / "escape").symlink_to("/etc")

    # Contains neither `..` nor `/etc/`, so the deny rule's patterns do not
    # match it. Confinement is what stops it.
    with pytest.raises(PermissionError, match="outside the permitted root"):
        await proxy.call("read_file", {"path": "escape/passwd"})


async def test_encoded_traversal_is_denied(proxy):
    with pytest.raises(PermissionError, match="percent-encoded"):
        await proxy.call("read_file", {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"})


async def test_undeclared_resource_is_refused_before_any_rule(tmp_path, adapter):
    # A policy that allows everything still cannot reach a resource the adapter
    # does not expose.
    policy = _policy(
        f"""
        version: 2
        default_action: allow
        audit_path: "{tmp_path / 'audit.db'}"
        rules:
          - resource: "**"
            action: allow
        """
    )
    proxy = ToolCallProxy(PolicyEngine(policy), adapter=adapter)

    with pytest.raises(PermissionError, match="does not declare resource 'rm_rf'"):
        await proxy.call("rm_rf", {"path": "/"})


async def test_boundary_refusals_are_audited(proxy, tmp_path):
    import aiosqlite

    with pytest.raises(PermissionError):
        await proxy.call("read_file", {"path": "../../etc/passwd"})

    async with aiosqlite.connect(str(tmp_path / "audit.db")) as db:
        async with db.execute(
            "SELECT tool, action, rule, enforced FROM audit_log"
        ) as cursor:
            rows = await cursor.fetchall()

    assert rows == [("read_file", "deny", "adapter:canonicalization", 1)]


async def test_normalization_is_recorded_in_the_audit_log(proxy, tmp_path):
    import json

    import aiosqlite

    await proxy.call("read_file", {"path": "sub/../notes.txt"})

    async with aiosqlite.connect(str(tmp_path / "audit.db")) as db:
        async with db.execute("SELECT normalization FROM audit_log") as cursor:
            (raw,), = await cursor.fetchall()

    assert any("path:" in note for note in json.loads(raw))


async def test_unnormalized_calls_record_no_normalization(proxy, tmp_path):
    import aiosqlite

    await proxy.call("ping", {})

    async with aiosqlite.connect(str(tmp_path / "audit.db")) as db:
        async with db.execute("SELECT normalization FROM audit_log") as cursor:
            (raw,), = await cursor.fetchall()

    assert raw is None


async def test_boundary_refusal_is_enforced_even_in_shadow_mode(tmp_path, adapter):
    """Shadow mode trials a policy; it does not disable adapter preconditions.

    A canonicalization failure means HYDRACUDA does not know what the request
    refers to, so there is no verdict to shadow.
    """
    policy = _policy(
        f"""
        version: 2
        mode: shadow
        default_action: allow
        audit_path: "{tmp_path / 'audit.db'}"
        rules:
          - resource: "**"
            action: allow
        """
    )
    proxy = ToolCallProxy(PolicyEngine(policy), adapter=adapter)

    with pytest.raises(PermissionError):
        await proxy.call("read_file", {"path": "../../etc/passwd"})


async def test_a_proxy_without_handler_or_adapter_is_a_usage_error(tmp_path):
    policy = _policy(
        f"""
        version: 2
        default_action: allow
        audit_path: "{tmp_path / 'audit.db'}"
        """
    )
    proxy = ToolCallProxy(PolicyEngine(policy))

    with pytest.raises(TypeError, match="needs a handler"):
        await proxy.call("anything", {})


async def test_an_explicit_handler_still_wins_over_the_adapter(proxy):
    async def handler(resource, params):
        return "from handler"

    assert await proxy.call("ping", {}, handler) == "from handler"
