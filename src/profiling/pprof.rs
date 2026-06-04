//! Building a `google.v1.Profile` (standard pprof) from resolved frames, interning
//! strings, functions and locations.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::proto::pprof;
use super::symbolize::Frame;

/// Builds a single `google.v1.Profile`, interning strings, functions and
/// locations. Locations are keyed by `(tgid, address)` since addresses are only
/// unique within a process.
pub(crate) struct ProfileBuilder {
    strings: Vec<String>,
    string_idx: HashMap<String, i64>,
    /// (function name, source file) -> function id.
    functions: HashMap<(String, String), u64>,
    locations: HashMap<(u32, u64), u64>,
    profile: pprof::Profile,
}

impl ProfileBuilder {
    pub(crate) fn new(period_ns: i64, duration_ns: i64) -> Self {
        let mut b = ProfileBuilder {
            strings: Vec::new(),
            string_idx: HashMap::new(),
            functions: HashMap::new(),
            locations: HashMap::new(),
            profile: pprof::Profile::default(),
        };
        // string_table[0] must be the empty string.
        b.intern("");
        b.profile.duration_nanos = duration_ns;

        let samples = b.intern("samples");
        let count = b.intern("count");
        let cpu = b.intern("cpu");
        let nanos = b.intern("nanoseconds");
        b.profile.sample_type = vec![
            pprof::ValueType {
                r#type: samples,
                unit: count,
            },
            pprof::ValueType {
                r#type: cpu,
                unit: nanos,
            },
        ];
        b.profile.period_type = Some(pprof::ValueType {
            r#type: cpu,
            unit: nanos,
        });
        b.profile.period = period_ns;
        // Prefer the "cpu" sample value (index 1) when displaying.
        b.profile.default_sample_type = cpu;
        b
    }

    fn intern(&mut self, s: &str) -> i64 {
        if let Some(&idx) = self.string_idx.get(s) {
            return idx;
        }
        let idx = self.strings.len() as i64;
        self.strings.push(s.to_owned());
        self.string_idx.insert(s.to_owned(), idx);
        idx
    }

    /// Intern a function by `(name, file)`. Two functions with the same name in
    /// different source files are distinct pprof functions. `file` is the source
    /// path (empty when unknown), stored as the function's `filename`.
    fn function(&mut self, name: &str, file: &str) -> u64 {
        let key = (name.to_owned(), file.to_owned());
        if let Some(&id) = self.functions.get(&key) {
            return id;
        }
        let id = self.functions.len() as u64 + 1; // ids are nonzero
        let name_idx = self.intern(name);
        let file_idx = self.intern(file); // "" -> 0
        self.functions.insert(key, id);
        self.profile.function.push(pprof::Function {
            id,
            name: name_idx,
            system_name: name_idx,
            filename: file_idx,
            start_line: 0,
        });
        id
    }

    pub(crate) fn location(&mut self, tgid: u32, frame: Frame) -> u64 {
        let key = (tgid, frame.address);
        // address 0 (unknown) can't be deduped per-process meaningfully, but a
        // shared "[unknown]" function keeps the table small.
        if frame.address != 0
            && let Some(&id) = self.locations.get(&key)
        {
            return id;
        }

        let lines: Vec<pprof::Line> = frame
            .lines
            .iter()
            .map(|fl| pprof::Line {
                function_id: self.function(&fl.name, &fl.file),
                line: fl.line,
            })
            .collect();

        let id = self.profile.location.len() as u64 + 1; // ids are nonzero
        self.profile.location.push(pprof::Location {
            id,
            mapping_id: 0,
            address: frame.address,
            line: lines,
            is_folded: false,
        });
        if frame.address != 0 {
            self.locations.insert(key, id);
        }
        id
    }

    pub(crate) fn add_sample(&mut self, location_id: Vec<u64>, count: u64) {
        let count = count as i64;
        self.profile.sample.push(pprof::Sample {
            location_id,
            value: vec![count, count * self.profile.period],
            label: Vec::new(),
        });
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.profile.sample.is_empty()
    }

    pub(crate) fn finish(mut self) -> pprof::Profile {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.profile.time_nanos = now;
        self.profile.string_table = self.strings;
        self.profile
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prost::Message;

    use super::super::symbolize::{Frame, FrameLine};
    use super::*;

    fn line(name: &str, file: &str, line: i64) -> FrameLine {
        FrameLine {
            name: Arc::from(name),
            file: Arc::from(file),
            line,
        }
    }

    #[test]
    fn profile_is_valid_pprof() {
        let mut b = ProfileBuilder::new(10_000_000, 10_000_000_000);
        let f1 = b.location(
            1234,
            Frame {
                address: 0x401000,
                lines: vec![line("main", "/src/main.rs", 10)],
            },
        );
        // Two inlined frames (innermost first) with source locations.
        let f2 = b.location(
            1234,
            Frame {
                address: 0x401100,
                lines: vec![
                    line("inlined_callee", "/src/lib.rs", 42),
                    line("do_work", "/src/lib.rs", 99),
                ],
            },
        );
        // Same address in a different process must yield a distinct location.
        let f3 = b.location(
            5678,
            Frame {
                address: 0x401000,
                lines: vec![line("main", "/src/main.rs", 10)],
            },
        );
        assert_ne!(f1, f3);
        b.add_sample(vec![f2, f1], 7);
        b.add_sample(vec![f3], 3);

        let profile = b.finish();
        assert_eq!(profile.string_table[0], "");
        let bytes = profile.encode_to_vec();
        let decoded = pprof::Profile::decode(&bytes[..]).expect("valid pprof");
        assert_eq!(decoded.sample.len(), 2);
        assert_eq!(decoded.sample[0].value, vec![7, 70_000_000]);

        // Source locations made it into the pprof: the inlined location carries
        // both lines, and its functions point at the right source file.
        let str_of = |idx: i64| decoded.string_table[idx as usize].as_str();
        let loc = decoded
            .location
            .iter()
            .find(|l| l.address == 0x401100)
            .expect("inlined location present");
        assert_eq!(
            loc.line.iter().map(|l| l.line).collect::<Vec<_>>(),
            [42, 99]
        );
        let func = |id: u64| decoded.function.iter().find(|f| f.id == id).unwrap();
        assert_eq!(str_of(func(loc.line[0].function_id).name), "inlined_callee");
        assert_eq!(
            str_of(func(loc.line[0].function_id).filename),
            "/src/lib.rs"
        );
    }
}
