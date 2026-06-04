use pyo3::prelude::*;

#[derive(Debug, Default, Clone)]
pub struct FeatureOutput {
    pub features: Vec<f32>,
    pub label: Vec<u8>,
    pub attack_idx: Vec<i32>,
    pub matched: Vec<bool>,
    pub flow_id: Vec<u64>,
    pub n_rows: usize,
}

impl FeatureOutput {
    pub fn with_capacity(n_rows: usize) -> Self {
        Self {
            features: Vec::with_capacity(n_rows * 38),
            label: Vec::with_capacity(n_rows),
            attack_idx: Vec::with_capacity(n_rows),
            matched: Vec::with_capacity(n_rows),
            flow_id: Vec::with_capacity(n_rows),
            n_rows: 0,
        }
    }
}

#[pyclass(name = "FeatureOutput", module = "raptorgate_pcap")]
pub struct PyFeatureOutput {
    pub inner: FeatureOutput,
}

#[pymethods]
impl PyFeatureOutput {
    #[getter]
    fn n_rows(&self) -> usize {
        self.inner.n_rows
    }

    #[getter]
    fn features(&self) -> Vec<f32> {
        self.inner.features.clone()
    }

    #[getter]
    fn label(&self) -> Vec<u8> {
        self.inner.label.clone()
    }

    #[getter]
    fn attack_idx(&self) -> Vec<i32> {
        self.inner.attack_idx.clone()
    }

    #[getter]
    fn matched(&self) -> Vec<bool> {
        self.inner.matched.clone()
    }

    #[getter]
    fn flow_id(&self) -> Vec<u64> {
        self.inner.flow_id.clone()
    }
}

impl From<FeatureOutput> for PyFeatureOutput {
    fn from(inner: FeatureOutput) -> Self {
        Self { inner }
    }
}
