pub mod error;
pub mod features;
pub mod flow_id;
pub mod index;
pub mod labels;
pub mod output;
pub mod parse;
pub mod stats;

use pyo3::prelude::*;

#[pymodule]
fn raptorgate_pcap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<labels::PyLabelIndex>()?;
    Ok(())
}
