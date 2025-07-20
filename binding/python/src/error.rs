use pyo3::exceptions::PyException;
use pyo3::prelude::*;

pyo3::create_exception!(
    synlink,
    SynlinkBaseException,
    PyException,
    "Base exception on the Synapse Network protocol"
);

/// A Python module implemented in Rust.
#[pymodule]
pub(crate) fn register_exception(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let error_m = PyModule::new(m.py(), "_error")?;
    error_m.add(
        "SynlinkBaseException",
        error_m.py().get_type::<SynlinkBaseException>(),
    )?;

    m.add_submodule(&error_m)
}
