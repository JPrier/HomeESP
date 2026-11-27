//! Prometheus text exposition with low-cardinality labels (no MACs, no device ids).

use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Default)]
pub struct Exposition {
    out: String,
    seen: BTreeMap<String, ()>,
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl Exposition {
    fn header(&mut self, name: &str, kind: &str, help: &str) {
        if self.seen.insert(name.to_string(), ()).is_none() {
            let _ = writeln!(self.out, "# HELP {name} {help}");
            let _ = writeln!(self.out, "# TYPE {name} {kind}");
        }
    }

    pub fn gauge(&mut self, name: &str, help: &str, labels: &[(&str, &str)], v: f64) {
        if !v.is_finite() {
            return;
        }
        self.header(name, "gauge", help);
        self.sample(name, labels, v);
    }

    pub fn counter(&mut self, name: &str, help: &str, labels: &[(&str, &str)], v: f64) {
        if !v.is_finite() {
            return;
        }
        self.header(name, "counter", help);
        self.sample(name, labels, v);
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], v: f64) {
        if !v.is_finite() {
            return; // unknown values are omitted, never exported as 0
        }
        if labels.is_empty() {
            let _ = writeln!(self.out, "{name} {v}");
        } else {
            let l: Vec<String> = labels
                .iter()
                .map(|(k, val)| format!("{k}=\"{}\"", escape(val)))
                .collect();
            let _ = writeln!(self.out, "{name}{{{}}} {v}", l.join(","));
        }
    }

    pub fn finish(self) -> String {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_and_escapes() {
        let mut e = Exposition::default();
        e.counter("ho_frames_total", "frames", &[("result", "ok")], 3.0);
        e.counter("ho_frames_total", "frames", &[("result", "bad\"x")], 1.0);
        e.gauge("ho_unknown", "omitted", &[], f64::NAN);
        let s = e.finish();
        assert_eq!(s.matches("# TYPE ho_frames_total counter").count(), 1);
        assert!(s.contains("result=\"bad\\\"x\""));
        assert!(!s.contains("ho_unknown"), "unknown values emit nothing");
    }
}
