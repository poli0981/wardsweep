//! What an audit scan reports.
//!
//! The report is the contract `docs/11-CLI-REFERENCE.md` gives `wardsweep
//! scan --json`: versioned, and changed only on a major release. It says what
//! was found, what was refused because the deny-list protects it, and what
//! could not be read — and a scan with anything in the last list is partial,
//! never clean.

use serde::Serialize;

use crate::catalog::schema::Risk;

/// The report's wire version, `"v"` in every JSON record.
pub const REPORT_VERSION: u32 = 1;

/// How sure a finding is that the artifact is the anti-cheat's
/// (`docs/05-DETECTION-ENGINE.md`, "Matching strategy").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// A high-weight signal and the publisher the catalog names.
    Confirmed,
    /// A high-weight signal with no publisher to check: the file is gone, the
    /// artifact is not a file, or verification failed for a reason other than
    /// the signature itself.
    Probable,
    /// The name or path matches and the signature names someone else, is
    /// invalid, or is absent. Never chosen for removal; reported prominently.
    Suspicious,
}

/// Which WOW64 view a registry artifact was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum RegView {
    /// The 64-bit view.
    #[serde(rename = "64")]
    Bits64,
    /// The 32-bit view, `WOW6432Node`.
    #[serde(rename = "32")]
    Bits32,
}

/// One thing found on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "artifact", rename_all = "snake_case")]
pub enum Artifact {
    /// A service, by name.
    Service {
        /// The service name.
        name: String,
        /// Its image as configured, when known.
        image: Option<String>,
        /// Present in `Services` but unknown to the service control manager
        /// (`docs/05`, "Not SCM alone").
        registry_only: bool,
    },
    /// A kernel driver, by file name.
    Driver {
        /// The file name the catalog names.
        file: String,
        /// The `Services` key registering it, when there is one.
        service: Option<String>,
        /// The image path, expanded.
        image: String,
        /// Whether the image is on disk. A missing image under a present key is
        /// not a removal: EA's minifilter has none while no game runs.
        image_present: bool,
    },
    /// A registry key, in one view. The same key in both views is two artifacts.
    RegistryKey {
        /// The key, as the catalog names it.
        key: String,
        /// The view it was found in.
        view: RegView,
    },
    /// A file or directory.
    Path {
        /// The path, expanded.
        path: String,
        /// Whether it is a directory.
        directory: bool,
    },
}

/// A finding: an artifact of one catalog entry, how sure the scan is, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The catalog entry's id.
    pub anticheat: String,
    /// How much damage removing it wrongly would do, as the catalog rates the
    /// anti-cheat.
    pub risk: Risk,
    /// What was found.
    #[serde(flatten)]
    pub artifact: Artifact,
    /// How sure the scan is that it is the anti-cheat's.
    pub classification: Classification,
    /// The signals behind the classification, in words.
    pub evidence: Vec<String>,
}

/// Something a catalog entry names that the deny-list protects. Reported, never
/// offered: catalog validation should have refused it, and a protected path
/// that reaches a scan says the catalog and the deny-list disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Protected {
    /// The catalog entry's id.
    pub anticheat: String,
    /// The path or key.
    pub target: String,
    /// The deny-list's reason.
    pub reason: String,
}

/// Something the scan could not read. Unreadable is never absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unreadable {
    /// The catalog entry's id, when the item belongs to one.
    pub anticheat: Option<String>,
    /// The service, key or path.
    pub item: String,
    /// Why, in the platform's terms.
    pub reason: String,
}

/// A stale record the scan saw and did not believe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disbelieved {
    /// The catalog entry's id.
    pub anticheat: String,
    /// The service name.
    pub item: String,
    /// What the source claimed and why it was not taken.
    pub reason: String,
}

/// Everything one audit found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// [`REPORT_VERSION`].
    pub v: u32,
    /// Artifacts found, in catalog order.
    pub findings: Vec<Finding>,
    /// Targets the deny-list protects.
    pub protected: Vec<Protected>,
    /// Records the scan saw and did not believe: an SCM entry for a service
    /// whose key is gone.
    pub disbelieved: Vec<Disbelieved>,
    /// What could not be read.
    pub unreadable: Vec<Unreadable>,
}

impl Report {
    /// Whether anything could not be read. A partial scan is never reported as
    /// clean (`docs/05`, "Access-denied handling").
    #[must_use]
    pub fn partial(&self) -> bool {
        !self.unreadable.is_empty()
    }

    /// How many findings have a classification.
    #[must_use]
    pub fn count(&self, classification: Classification) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.classification == classification)
            .count()
    }

    /// The report as `wardsweep scan --json` writes it (`docs/11`): one JSON
    /// object per line, each carrying `"v"` and a `"type"` — `finding`,
    /// `protected`, `disbelieved` or `unreadable` — and a closing `summary`.
    ///
    /// # Errors
    ///
    /// Returns serde's error if a record cannot be written as JSON, which the
    /// types here do not give it a way to do.
    pub fn to_ndjson(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::new();
        for finding in &self.findings {
            lines.push(record("finding", finding)?);
        }
        for protected in &self.protected {
            lines.push(record("protected", protected)?);
        }
        for disbelieved in &self.disbelieved {
            lines.push(record("disbelieved", disbelieved)?);
        }
        for unreadable in &self.unreadable {
            lines.push(record("unreadable", unreadable)?);
        }
        lines.push(record(
            "summary",
            &Summary {
                findings: self.findings.len(),
                confirmed: self.count(Classification::Confirmed),
                probable: self.count(Classification::Probable),
                suspicious: self.count(Classification::Suspicious),
                protected: self.protected.len(),
                disbelieved: self.disbelieved.len(),
                unreadable: self.unreadable.len(),
                partial: self.partial(),
            },
        )?);
        let mut text = lines.join("\n");
        text.push('\n');
        Ok(text)
    }
}

/// One line of `--json` output: the version, the record's type, and its fields.
#[derive(Serialize)]
struct Record<'a, T> {
    v: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(flatten)]
    body: &'a T,
}

fn record<T: Serialize>(kind: &'static str, body: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(&Record {
        v: REPORT_VERSION,
        kind,
        body,
    })
}

/// The closing line of `--json` output.
#[derive(Serialize)]
struct Summary {
    findings: usize,
    confirmed: usize,
    probable: usize,
    suspicious: usize,
    protected: usize,
    disbelieved: usize,
    unreadable: usize,
    partial: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_json_line_carries_its_version_and_type() {
        let report = Report {
            v: REPORT_VERSION,
            findings: vec![Finding {
                anticheat: "example-ac".to_owned(),
                risk: Risk::Critical,
                artifact: Artifact::RegistryKey {
                    key: "HKLM\\SOFTWARE\\Example\\AC".to_owned(),
                    view: RegView::Bits32,
                },
                classification: Classification::Probable,
                evidence: vec!["present in the 32-bit view (WOW6432Node)".to_owned()],
            }],
            protected: Vec::new(),
            disbelieved: Vec::new(),
            unreadable: vec![Unreadable {
                anticheat: None,
                item: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Locked".to_owned(),
                reason: "access denied".to_owned(),
            }],
        };

        let text = report.to_ndjson().expect("the report is JSON");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is one JSON object"))
            .collect();

        assert!(text.ends_with('\n'));
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line["v"] == 1));
        assert_eq!(lines[0]["type"], "finding");
        assert_eq!(lines[0]["artifact"], "registry_key");
        assert_eq!(lines[0]["view"], "32");
        assert_eq!(lines[0]["classification"], "probable");
        assert_eq!(lines[0]["risk"], "critical");
        assert_eq!(lines[1]["type"], "unreadable");
        assert_eq!(lines[2]["type"], "summary");
        assert_eq!(lines[2]["probable"], 1);
        assert_eq!(lines[2]["partial"], true);
    }
}
