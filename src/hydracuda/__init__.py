"""HYDRACUDA - Runtime policy enforcement for AI tool calls."""

__version__ = "0.3.1"

from hydracuda._backend import engine_backend, engine_version
from hydracuda.adapters import (
    Adapter,
    AdapterError,
    NormalizedAction,
    ResourceSpec,
    UndeclaredResource,
)
from hydracuda.adapters.local_tools import LocalToolsAdapter
from hydracuda.adapters.registry import build_adapter, register_adapter_type
from hydracuda.canonical import CanonicalizationError, canonicalize_path
from hydracuda.engine import Decision, PolicyEngine
from hydracuda.introspect import (
    CaseResult,
    Diagnostic,
    PlanEntry,
    Report,
    analyze,
    plan,
    run_tests,
)
from hydracuda.policy import (
    AdapterSpec,
    Policy,
    PolicyError,
    Rule,
    TestCase,
    ToolPolicy,
    load_policy,
    parse_policy,
)
from hydracuda.proxy import ContextError, ReviewRequired, ToolCallProxy

__all__ = [
    "Adapter",
    "AdapterError",
    "AdapterSpec",
    "CanonicalizationError",
    "CaseResult",
    "ContextError",
    "Decision",
    "Diagnostic",
    "LocalToolsAdapter",
    "NormalizedAction",
    "PlanEntry",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "Report",
    "ResourceSpec",
    "ReviewRequired",
    "Rule",
    "TestCase",
    "ToolCallProxy",
    "ToolPolicy",
    "UndeclaredResource",
    "analyze",
    "build_adapter",
    "canonicalize_path",
    "engine_backend",
    "engine_version",
    "load_policy",
    "parse_policy",
    "plan",
    "register_adapter_type",
    "run_tests",
]
