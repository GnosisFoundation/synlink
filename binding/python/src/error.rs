use pyo3::prelude::*;
use pyo3::exceptions::PyException;

pyo3::create_exception!(
    synlink,
    IpmsBaseException,
    PyException,
    "Custom Base exception on the SL protocol"
);

/// A Python module implemented in Rust.
#[pymodule]
pub(crate) fn register_exception(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let error_m = PyModule::new(m.py(), "_error")?;
    error_m.add(
        "IpmsBaseException",
        error_m.py().get_type::<IpmsBaseException>(),
    )?;

    m.add_submodule(m)
}
