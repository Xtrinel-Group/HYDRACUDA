//! Adapter interface.
//!
//! An adapter answers "what exists" — the resources and actions an integration
//! exposes. Policy answers "what is permitted". The two are connected only by
//! the resource vocabulary the adapter declares, so the engine never needs to
//! know what an adapter does internally.
//!
//! An adapter has one security responsibility the engine cannot take on:
//! [`Adapter::normalize`] turns a caller-supplied request into its canonical
//! form before any rule is evaluated, and the canonical form is what gets
//! executed.
//!
//! ## Why this trait has no `execute`
//!
//! The Python ABC does, because the Python package both decides and calls. This
//! trait deliberately stops at normalization: `core` is the decision engine, and
//! giving it a way to run a caller's code would put an async runtime and a
//! side-effecting method inside the crate whose whole claim is that it has
//! neither. Execution stays where the handlers already live — the integrator's
//! Python process, via the bindings. The standalone CLI never executes anything
//! at all.
//!
//! An adapter is therefore implementable from Rust *or* from Python: a Python
//! adapter satisfies this trait through the bindings without either side having
//! to know which language the other is written in.

use indexmap::IndexMap;

use crate::engine::Fields;

/// An adapter could not serve a request.
///
/// Each variant is a refusal, not a policy denial — the distinction matters
/// because a refusal is enforced even under `mode: shadow`. Shadow mode trials a
/// policy; it does not disable the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// The request named a resource the adapter does not declare.
    ///
    /// Distinct from a policy denial: the resource does not exist as far as this
    /// adapter is concerned, so no rule — however broad — should reach it.
    UndeclaredResource(String),
    /// A parameter could not be canonicalized safely, or escaped its permitted
    /// root. Every caller treats this as a denial.
    Canonicalization(String),
    /// Any other adapter failure.
    Other(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::UndeclaredResource(message)
            | AdapterError::Canonicalization(message)
            | AdapterError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for AdapterError {}

/// One resource an adapter exposes.
///
/// `path_parameters` names the parameters holding filesystem paths. Declaring
/// them is what causes them to be canonicalized and confined before evaluation,
/// so an omission here is a security-relevant omission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceSpec {
    pub name: String,
    pub description: String,
    pub parameters: Vec<String>,
    pub path_parameters: Vec<String>,
}

impl ResourceSpec {
    pub fn new(name: impl Into<String>) -> Self {
        ResourceSpec {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn with_parameters<I, S>(mut self, parameters: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.parameters = parameters.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_path_parameters<I, S>(mut self, path_parameters: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.path_parameters = path_parameters.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

/// A request after canonicalization, ready to be evaluated and executed.
#[derive(Debug, Clone)]
pub struct NormalizedAction {
    pub resource: String,
    pub params: Fields,
    pub notes: Vec<String>,
}

/// Declares a resource surface, independent of how policy evaluates it.
pub trait Adapter {
    /// Unique instance name, used in diagnostics and audit records.
    fn name(&self) -> &str;

    /// Every resource this adapter exposes, in declaration order.
    fn resource_specs(&self) -> &[ResourceSpec];

    /// Declared resource names, in declaration order.
    fn resources(&self) -> Vec<String> {
        self.resource_specs()
            .iter()
            .map(|spec| spec.name.clone())
            .collect()
    }

    /// The spec for a resource, or `None` when it is not declared.
    fn spec_for(&self, resource: &str) -> Option<&ResourceSpec> {
        self.resource_specs()
            .iter()
            .find(|spec| spec.name == resource)
    }

    /// True when this adapter exposes `resource`.
    fn declares(&self, resource: &str) -> bool {
        self.spec_for(resource).is_some()
    }

    /// Canonicalize a request before it is evaluated.
    ///
    /// The default implementation is the identity transform. Override it
    /// whenever a parameter has a canonical form that differs from its spelling
    /// — paths, URLs, identifiers with optional prefixes — and return
    /// [`AdapterError::Canonicalization`] for input that cannot be canonicalized
    /// safely. Callers treat that as a denial.
    fn normalize(&self, resource: &str, params: &Fields) -> Result<NormalizedAction, AdapterError> {
        if !self.declares(resource) {
            return Err(AdapterError::UndeclaredResource(format!(
                "adapter '{}' does not declare resource '{}'",
                self.name(),
                resource
            )));
        }
        Ok(NormalizedAction {
            resource: resource.to_string(),
            params: params.clone(),
            notes: Vec::new(),
        })
    }
}

/// An adapter that declares a resource surface and nothing else.
///
/// This is what a policy file's `adapters:` block can produce on its own: the
/// resource vocabulary is in the file, but the callables live in the
/// integrator's process. Such a surface can be validated and planned against; it
/// cannot execute, and it does not canonicalize — path canonicalization arrives
/// with the `local_tools` port.
#[derive(Debug, Default)]
pub struct DeclaredSurface {
    name: String,
    specs: Vec<ResourceSpec>,
    index: IndexMap<String, usize>,
}

impl DeclaredSurface {
    pub fn new(name: impl Into<String>) -> Self {
        DeclaredSurface {
            name: name.into(),
            specs: Vec::new(),
            index: IndexMap::new(),
        }
    }

    /// Declare a resource. A duplicate name is an error, as it is in Python:
    /// two specs under one name make "what exists" ambiguous.
    pub fn declare(&mut self, spec: ResourceSpec) -> Result<(), AdapterError> {
        if self.index.contains_key(&spec.name) {
            return Err(AdapterError::Other(format!(
                "adapter '{}' already declares resource '{}'",
                self.name, spec.name
            )));
        }
        // Declaring a path parameter that is not a parameter at all is a typo
        // with security consequences: nothing would be canonicalized.
        if !spec.parameters.is_empty() {
            let mut unknown: Vec<&String> = spec
                .path_parameters
                .iter()
                .filter(|p| !spec.parameters.contains(p))
                .collect();
            unknown.sort();
            if !unknown.is_empty() {
                let unknown: Vec<String> = unknown.into_iter().cloned().collect();
                let mut parameters = spec.parameters.clone();
                parameters.sort();
                return Err(AdapterError::Other(format!(
                    "resource '{}': path_parameters {} are not listed in parameters {}",
                    spec.name,
                    crate::value::py_repr_str_list(&unknown),
                    crate::value::py_repr_str_list(&parameters),
                )));
            }
        }
        self.index.insert(spec.name.clone(), self.specs.len());
        self.specs.push(spec);
        Ok(())
    }
}

impl Adapter for DeclaredSurface {
    fn name(&self) -> &str {
        &self.name
    }

    fn resource_specs(&self) -> &[ResourceSpec] {
        &self.specs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    fn surface() -> DeclaredSurface {
        let mut surface = DeclaredSurface::new("local");
        surface
            .declare(
                ResourceSpec::new("fs.read")
                    .with_parameters(["path"])
                    .with_path_parameters(["path"]),
            )
            .unwrap();
        surface.declare(ResourceSpec::new("fs.list")).unwrap();
        surface
    }

    #[test]
    fn a_declared_surface_reports_what_it_exposes() {
        let surface = surface();
        assert_eq!(surface.name(), "local");
        assert_eq!(surface.resources(), vec!["fs.read", "fs.list"]);
        assert!(surface.declares("fs.read"));
        assert!(!surface.declares("fs.write"));
        assert_eq!(
            surface.spec_for("fs.read").unwrap().path_parameters,
            vec!["path"]
        );
        assert!(surface.spec_for("fs.write").is_none());
    }

    #[test]
    fn the_default_normalize_is_the_identity_transform() {
        let surface = surface();
        let mut params = Fields::new();
        params.insert("path".into(), Value::Str("../etc".into()));
        let normalized = surface.normalize("fs.read", &params).unwrap();
        assert_eq!(normalized.resource, "fs.read");
        assert_eq!(normalized.params["path"].as_str(), Some("../etc"));
        assert!(normalized.notes.is_empty());
    }

    #[test]
    fn an_undeclared_resource_is_refused_before_any_rule_is_consulted() {
        let error = surface().normalize("fs.write", &Fields::new()).unwrap_err();
        assert_eq!(
            error,
            AdapterError::UndeclaredResource(
                "adapter 'local' does not declare resource 'fs.write'".into()
            )
        );
    }

    #[test]
    fn a_duplicate_resource_name_is_rejected() {
        let mut surface = surface();
        let error = surface.declare(ResourceSpec::new("fs.read")).unwrap_err();
        assert_eq!(
            error,
            AdapterError::Other("adapter 'local' already declares resource 'fs.read'".into())
        );
    }

    #[test]
    fn a_path_parameter_must_be_a_parameter() {
        let mut surface = DeclaredSurface::new("local");
        let error = surface
            .declare(
                ResourceSpec::new("fs.read")
                    .with_parameters(["path"])
                    .with_path_parameters(["target"]),
            )
            .unwrap_err();
        assert_eq!(
            error,
            AdapterError::Other(
                "resource 'fs.read': path_parameters ['target'] are not listed in \
                 parameters ['path']"
                    .into()
            )
        );
    }
}
