use std::sync::OnceLock;

use pyo3::prelude::*;
use pyo3::Bound as PyBound;
use pyo3::exceptions::PyModuleNotFoundError;

pub(crate) fn get_module<'a>(
    py: Python<'a>,
    cell: &'static OnceLock<Py<PyModule>>,
) -> PyResult<&'a PyBound<'a, PyModule>> {
    let module: &PyBound<'a, PyModule> = cell
        .get()
        .ok_or_else(|| PyModuleNotFoundError::new_err("Could not find module"))?
        .bind(py);
    Ok(module)
}