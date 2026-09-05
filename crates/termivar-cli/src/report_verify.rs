//! Read-only verification of one explicitly selected report-bundle directory.
//!
//! Verification checks the supported layout, manifest, captured payload bytes,
//! and the display-only assessment summary. It owns no scanner, credential,
//! provider, or network authority and never executes the bundled HTML.

use clap::{Args, ValueEnum};
use same_file::Handle;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use termivar_scanner::reporting::comparison::{
    import_assessment_summary, ComparisonError, MAX_COMPARISON_INPUT_BYTES,
};

use crate::report_bundle::{
    ASSESSMENT_HTML_NAME, ASSESSMENT_JSON_NAME, MANIFEST_NAME, MAX_MANIFEST_BYTES,
    REPORT_BUNDLE_SCHEMA,
};

const VERIFICATION_SCHEMA: &str = "termivar-report-verification/v1";
const MAX_VERIFICATION_OUTPUT_BYTES: usize = 64 * 1_024;
const MAX_VERSION_BYTES: usize = 128;
const MAX_SUBJECT_COUNT: u64 = 1_024;
const MAX_ITEM_COUNT: u64 = 4_096;
const EXPECTED_PRODUCT: &str = "Termivar";
const EXPECTED_PROFILE: &str = "web-review";
const EXPECTED_STATUS: &str = "complete";

#[derive(Args)]
pub(crate) struct ReportVerifyArgs {
    /// Existing report-bundle directory to inspect without modifying it.
    #[arg(long = "dir", value_name = "DIRECTORY")]
    directory: PathBuf,
    /// Render the bounded verification result as text or JSON.
    #[arg(long, value_enum, default_value_t = CliVerificationFormat::Text)]
    format: CliVerificationFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum CliVerificationFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportVerifyError {
    LimitExceeded,
    EncodingFailed,
    WriteFailed,
}

impl fmt::Display for ReportVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "report verification output exceeds the byte limit",
            Self::EncodingFailed => "report verification output could not be encoded",
            Self::WriteFailed => "report verification output could not be written",
        })
    }
}

impl std::error::Error for ReportVerifyError {}

pub(crate) fn run(args: ReportVerifyArgs) -> Result<ExitCode, ReportVerifyError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    run_with_writer(args, &mut output)
}

fn run_with_writer(
    args: ReportVerifyArgs,
    output: &mut impl Write,
) -> Result<ExitCode, ReportVerifyError> {
    let result = verify_directory(&args.directory);
    let rendered = render_result(&result, args.format)?;
    output
        .write_all(rendered.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| ReportVerifyError::WriteFailed)?;
    Ok(if result.is_match() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerificationStatus {
    IntegrityMatch,
    NotVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReasonCode {
    AssessmentAmbiguousIdentity,
    AssessmentInvalidDocument,
    AssessmentInvalidJson,
    AssessmentSummaryMismatch,
    AssessmentUnsupportedDocument,
    ConcurrentChangeObserved,
    DirectoryUnavailable,
    HtmlInvalidUtf8,
    InvalidManifest,
    InvalidManifestContract,
    ManifestTooLarge,
    ManifestUnavailable,
    MissingAssessmentHtml,
    MissingAssessmentJson,
    MissingManifest,
    PayloadDigestMismatch,
    PayloadLengthMismatch,
    PayloadTooLarge,
    PayloadUnavailable,
    UnsupportedManifestSchema,
    UnsupportedPath,
    UnexpectedLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckState {
    CheckedMatched,
    CheckedMismatched,
    NotChecked,
}

#[derive(Debug, Serialize)]
struct VerificationResult {
    schema: &'static str,
    status: VerificationStatus,
    reason_codes: BTreeSet<ReasonCode>,
    manifest: ManifestResult,
    checks: VerificationChecks,
    trust: TrustLimits,
}

impl VerificationResult {
    fn new() -> Self {
        Self {
            schema: VERIFICATION_SCHEMA,
            status: VerificationStatus::NotVerified,
            reason_codes: BTreeSet::new(),
            manifest: ManifestResult::default(),
            checks: VerificationChecks::new(),
            trust: TrustLimits {
                producer_source_authenticity: "not_established",
                html_content_equivalence_or_executable_safety: "not_established",
                original_scan_scope_findings_and_remediation: "not_evaluated",
                filesystem_snapshot_after_this_invocation: "not_established",
            },
        }
    }

    fn reject(&mut self, reason: ReasonCode) {
        self.reason_codes.insert(reason);
        self.status = VerificationStatus::NotVerified;
    }

    fn finish(&mut self) {
        if self.reason_codes.is_empty()
            && self.checks.layout == CheckState::CheckedMatched
            && self.checks.manifest == CheckState::CheckedMatched
            && self.checks.assessment_html.state == CheckState::CheckedMatched
            && self.checks.assessment_html.utf8 == Some(CheckState::CheckedMatched)
            && self.checks.assessment_json.state == CheckState::CheckedMatched
            && self.checks.assessment_document == CheckState::CheckedMatched
            && self.checks.assessment_summary == CheckState::CheckedMatched
        {
            self.status = VerificationStatus::IntegrityMatch;
        }
    }

    fn is_match(&self) -> bool {
        self.status == VerificationStatus::IntegrityMatch
    }
}

#[derive(Debug, Default, Serialize)]
struct ManifestResult {
    schema: Option<&'static str>,
    sha256: Option<String>,
    producer_product: Option<&'static str>,
    producer_version: Option<String>,
    profile: Option<&'static str>,
    assessment_status: Option<&'static str>,
    subject_count: Option<u64>,
    item_count: Option<u64>,
}

#[derive(Debug, Serialize)]
struct VerificationChecks {
    layout: CheckState,
    manifest: CheckState,
    assessment_html: FileCheck,
    assessment_json: FileCheck,
    assessment_document: CheckState,
    assessment_summary: CheckState,
}

impl VerificationChecks {
    fn new() -> Self {
        Self {
            layout: CheckState::NotChecked,
            manifest: CheckState::NotChecked,
            assessment_html: FileCheck::new(ASSESSMENT_HTML_NAME, true),
            assessment_json: FileCheck::new(ASSESSMENT_JSON_NAME, false),
            assessment_document: CheckState::NotChecked,
            assessment_summary: CheckState::NotChecked,
        }
    }
}

#[derive(Debug, Serialize)]
struct FileCheck {
    name: &'static str,
    state: CheckState,
    expected_byte_length: Option<u64>,
    observed_byte_length: Option<u64>,
    expected_sha256: Option<String>,
    observed_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    utf8: Option<CheckState>,
}

impl FileCheck {
    fn new(name: &'static str, check_utf8: bool) -> Self {
        Self {
            name,
            state: CheckState::NotChecked,
            expected_byte_length: None,
            observed_byte_length: None,
            expected_sha256: None,
            observed_sha256: None,
            utf8: check_utf8.then_some(CheckState::NotChecked),
        }
    }

    fn set_expected(&mut self, expected: &ExpectedFile) {
        self.expected_byte_length = Some(expected.byte_length);
        self.expected_sha256 = Some(expected.sha256.clone());
    }
}

#[derive(Debug, Serialize)]
struct TrustLimits {
    producer_source_authenticity: &'static str,
    html_content_equivalence_or_executable_safety: &'static str,
    original_scan_scope_findings_and_remediation: &'static str,
    filesystem_snapshot_after_this_invocation: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    schema: String,
    producer: ManifestProducerWire,
    assessment: ManifestAssessmentWire,
    files: [ManifestFileWire; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestProducerWire {
    product: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAssessmentWire {
    profile: String,
    status: String,
    subject_count: u64,
    item_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFileWire {
    name: String,
    format: String,
    media_type: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Clone)]
struct ExpectedFile {
    byte_length: u64,
    sha256: String,
}

struct ValidatedManifest {
    producer_version: String,
    subject_count: u64,
    item_count: u64,
    html: ExpectedFile,
    json: ExpectedFile,
}

fn parse_manifest(bytes: &[u8]) -> Result<ValidatedManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::Invalid);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let manifest = ManifestWire::deserialize(&mut decoder).map_err(|_| ManifestError::Invalid)?;
    decoder.end().map_err(|_| ManifestError::Invalid)?;
    if manifest.schema != REPORT_BUNDLE_SCHEMA {
        return Err(ManifestError::UnsupportedSchema);
    }
    if manifest.producer.product != EXPECTED_PRODUCT
        || manifest.producer.version.is_empty()
        || manifest.producer.version.len() > MAX_VERSION_BYTES
        || Version::parse(&manifest.producer.version).is_err()
        || manifest.assessment.profile != EXPECTED_PROFILE
        || manifest.assessment.status != EXPECTED_STATUS
        || manifest.assessment.subject_count == 0
        || manifest.assessment.subject_count > MAX_SUBJECT_COUNT
        || manifest.assessment.item_count > MAX_ITEM_COUNT
    {
        return Err(ManifestError::InvalidContract);
    }
    let mut html = None;
    let mut json = None;
    for file in manifest.files {
        let destination = match file.name.as_str() {
            ASSESSMENT_HTML_NAME => &mut html,
            ASSESSMENT_JSON_NAME => &mut json,
            _ => return Err(ManifestError::InvalidContract),
        };
        if destination.is_some() {
            return Err(ManifestError::InvalidContract);
        }
        let (format, media_type) = if file.name == ASSESSMENT_HTML_NAME {
            ("html", "text/html; charset=utf-8")
        } else {
            ("json", "application/json")
        };
        if file.format != format
            || file.media_type != media_type
            || file.byte_length == 0
            || file.byte_length > MAX_COMPARISON_INPUT_BYTES as u64
            || !is_lowercase_sha256(&file.sha256)
        {
            return Err(ManifestError::InvalidContract);
        }
        *destination = Some(ExpectedFile {
            byte_length: file.byte_length,
            sha256: file.sha256,
        });
    }
    Ok(ValidatedManifest {
        producer_version: manifest.producer.version,
        subject_count: manifest.assessment.subject_count,
        item_count: manifest.assessment.item_count,
        html: html.ok_or(ManifestError::InvalidContract)?,
        json: json.ok_or(ManifestError::InvalidContract)?,
    })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestError {
    Invalid,
    UnsupportedSchema,
    InvalidContract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedFile {
    Manifest,
    Html,
    Json,
}

trait VerificationHook {
    fn after_read(&mut self, _file: FixedFile) {}
    fn before_final_layout(&mut self) {}
}

struct NoopVerificationHook;

impl VerificationHook for NoopVerificationHook {}

struct CapturedFile {
    bytes: Vec<u8>,
    byte_length: u64,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureError {
    Unavailable,
    TooLarge,
    Changed,
}

fn capture_regular_file(
    path: &Path,
    limit: usize,
    kind: FixedFile,
    hook: &mut impl VerificationHook,
) -> Result<CapturedFile, CaptureError> {
    let mut file = crate::auth_input::open_regular_file(path.to_owned())
        .map_err(|_| CaptureError::Unavailable)?;
    let identity = Handle::from_file(file.try_clone().map_err(|_| CaptureError::Unavailable)?)
        .map_err(|_| CaptureError::Unavailable)?;
    let before = file.metadata().map_err(|_| CaptureError::Unavailable)?;
    if before.len() > limit as u64 {
        return Err(CaptureError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(limit).min(limit));
    Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CaptureError::Unavailable)?;
    if bytes.len() > limit {
        return Err(CaptureError::TooLarge);
    }
    hook.after_read(kind);
    let after = file.metadata().map_err(|_| CaptureError::Changed)?;
    if before.len() != after.len() || after.len() != bytes.len() as u64 {
        return Err(CaptureError::Changed);
    }
    let current =
        crate::auth_input::open_regular_file(path.to_owned()).map_err(|_| CaptureError::Changed)?;
    let current_identity = Handle::from_file(current).map_err(|_| CaptureError::Changed)?;
    if current_identity != identity {
        return Err(CaptureError::Changed);
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok(CapturedFile {
        byte_length: bytes.len() as u64,
        bytes,
        sha256,
    })
}

struct OpenedDirectory {
    file: File,
    identity: Handle,
}

fn open_directory(path: &Path) -> Result<OpenedDirectory, ()> {
    let file = open_directory_no_follow(path)?;
    let identity = Handle::from_file(file.try_clone().map_err(|_| ())?).map_err(|_| ())?;
    Ok(OpenedDirectory { file, identity })
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> Result<File, ()> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
        .open(path)
        .map_err(|_| ())?;
    file.metadata()
        .map_err(|_| ())?
        .is_dir()
        .then_some(file)
        .ok_or(())
}

#[cfg(windows)]
fn open_directory_no_follow(path: &Path) -> Result<File, ()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(0)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    (metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0)
        .then_some(file)
        .ok_or(())
}

#[cfg(not(any(unix, windows)))]
fn open_directory_no_follow(_: &Path) -> Result<File, ()> {
    Err(())
}

impl OpenedDirectory {
    fn remains_at(&self, path: &Path) -> bool {
        let Ok(current) = open_directory_no_follow(path) else {
            return false;
        };
        Handle::from_file(current).is_ok_and(|identity| identity == self.identity)
            && self.file.metadata().is_ok_and(|metadata| metadata.is_dir())
    }
}

#[derive(Default, PartialEq, Eq)]
struct Layout {
    manifest: bool,
    html: bool,
    json: bool,
    unexpected: bool,
    enumeration_complete: bool,
}

impl Layout {
    fn complete(&self) -> bool {
        self.manifest && self.html && self.json && !self.unexpected
    }
}

fn inspect_layout(path: &Path) -> Result<Layout, ()> {
    let mut layout = Layout::default();
    let mut count = 0usize;
    for entry in fs::read_dir(path).map_err(|_| ())? {
        count = count.saturating_add(1);
        if count > 3 {
            layout.unexpected = true;
            return Ok(layout);
        }
        let entry = entry.map_err(|_| ())?;
        let regular = entry.file_type().map_err(|_| ())?.is_file();
        let name = entry.file_name();
        let destination = if name == MANIFEST_NAME {
            &mut layout.manifest
        } else if name == ASSESSMENT_HTML_NAME {
            &mut layout.html
        } else if name == ASSESSMENT_JSON_NAME {
            &mut layout.json
        } else {
            layout.unexpected = true;
            return Ok(layout);
        };
        if !regular || *destination {
            layout.unexpected = true;
            return Ok(layout);
        }
        *destination = true;
    }
    layout.enumeration_complete = true;
    Ok(layout)
}

fn verify_directory(path: &Path) -> VerificationResult {
    let mut hook = NoopVerificationHook;
    verify_directory_with(path, &mut hook)
}

fn verify_directory_with(path: &Path, hook: &mut impl VerificationHook) -> VerificationResult {
    let mut result = VerificationResult::new();
    if crate::report_compare::validate_local_path(path).is_err() {
        result.reject(ReasonCode::UnsupportedPath);
        return result;
    }
    let Ok(directory) = open_directory(path) else {
        result.reject(ReasonCode::DirectoryUnavailable);
        return result;
    };
    let Ok(initial_layout) = inspect_layout(path) else {
        result.reject(ReasonCode::DirectoryUnavailable);
        return result;
    };
    if !directory.remains_at(path) {
        result.checks.layout = CheckState::CheckedMismatched;
        result.reject(ReasonCode::ConcurrentChangeObserved);
        return result;
    }
    record_layout(&initial_layout, &mut result);
    if !initial_layout.enumeration_complete {
        return finish_with_final_layout(path, &directory, &initial_layout, hook, result);
    }
    if !initial_layout.manifest {
        return finish_with_final_layout(path, &directory, &initial_layout, hook, result);
    }

    let manifest_path = path.join(MANIFEST_NAME);
    let manifest_capture = match capture_regular_file(
        &manifest_path,
        MAX_MANIFEST_BYTES,
        FixedFile::Manifest,
        hook,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            record_capture_error(error, true, &mut result);
            return finish_with_final_layout(path, &directory, &initial_layout, hook, result);
        },
    };
    result.manifest.sha256 = Some(manifest_capture.sha256);
    let manifest = match parse_manifest(&manifest_capture.bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            result.checks.manifest = CheckState::CheckedMismatched;
            result.reject(match error {
                ManifestError::Invalid => ReasonCode::InvalidManifest,
                ManifestError::UnsupportedSchema => ReasonCode::UnsupportedManifestSchema,
                ManifestError::InvalidContract => ReasonCode::InvalidManifestContract,
            });
            return finish_with_final_layout(path, &directory, &initial_layout, hook, result);
        },
    };
    result.checks.manifest = CheckState::CheckedMatched;
    result.manifest.schema = Some(REPORT_BUNDLE_SCHEMA);
    result.manifest.producer_product = Some(EXPECTED_PRODUCT);
    result.manifest.producer_version = Some(manifest.producer_version.clone());
    result.manifest.profile = Some(EXPECTED_PROFILE);
    result.manifest.assessment_status = Some(EXPECTED_STATUS);
    result.manifest.subject_count = Some(manifest.subject_count);
    result.manifest.item_count = Some(manifest.item_count);
    result.checks.assessment_html.set_expected(&manifest.html);
    result.checks.assessment_json.set_expected(&manifest.json);

    verify_html(path, &initial_layout, &manifest.html, hook, &mut result);
    let json = verify_json_payload(path, &initial_layout, &manifest.json, hook, &mut result);
    if let Some(bytes) = json {
        match import_assessment_summary(&bytes) {
            Ok(summary) => {
                result.checks.assessment_document = CheckState::CheckedMatched;
                if summary.schema() == "venom-rendered-assessment/v1"
                    && summary.profile() == EXPECTED_PROFILE
                    && summary.status() == EXPECTED_STATUS
                    && summary.subject_count() == manifest.subject_count
                    && summary.item_count() == manifest.item_count
                {
                    result.checks.assessment_summary = CheckState::CheckedMatched;
                } else {
                    result.checks.assessment_summary = CheckState::CheckedMismatched;
                    result.reject(ReasonCode::AssessmentSummaryMismatch);
                }
            },
            Err(error) => {
                result.checks.assessment_document = CheckState::CheckedMismatched;
                result.reject(match error {
                    ComparisonError::InvalidJson => ReasonCode::AssessmentInvalidJson,
                    ComparisonError::UnsupportedDocument => {
                        ReasonCode::AssessmentUnsupportedDocument
                    },
                    ComparisonError::AmbiguousIdentity => ReasonCode::AssessmentAmbiguousIdentity,
                    ComparisonError::InputLimitExceeded
                    | ComparisonError::InvalidDocument
                    | ComparisonError::OutputLimitExceeded
                    | ComparisonError::Serialization => ReasonCode::AssessmentInvalidDocument,
                    _ => ReasonCode::AssessmentInvalidDocument,
                });
            },
        }
    }
    finish_with_final_layout(path, &directory, &initial_layout, hook, result)
}

fn record_layout(layout: &Layout, result: &mut VerificationResult) {
    if layout.complete() {
        result.checks.layout = CheckState::CheckedMatched;
    } else {
        result.checks.layout = CheckState::CheckedMismatched;
        if !layout.enumeration_complete {
            result.reject(ReasonCode::UnexpectedLayout);
            return;
        }
        if !layout.manifest {
            result.reject(ReasonCode::MissingManifest);
        }
        if !layout.html {
            result.reject(ReasonCode::MissingAssessmentHtml);
        }
        if !layout.json {
            result.reject(ReasonCode::MissingAssessmentJson);
        }
    }
}

fn finish_with_final_layout(
    path: &Path,
    directory: &OpenedDirectory,
    initial_layout: &Layout,
    hook: &mut impl VerificationHook,
    mut result: VerificationResult,
) -> VerificationResult {
    hook.before_final_layout();
    let layout_changed = match inspect_layout(path) {
        Ok(layout) if initial_layout.enumeration_complete => layout != *initial_layout,
        Ok(layout) => layout.enumeration_complete,
        Err(()) => true,
    };
    if !directory.remains_at(path) || layout_changed {
        result.checks.layout = CheckState::CheckedMismatched;
        result.reject(ReasonCode::ConcurrentChangeObserved);
    }
    result.finish();
    result
}

fn verify_html(
    directory: &Path,
    layout: &Layout,
    expected: &ExpectedFile,
    hook: &mut impl VerificationHook,
    result: &mut VerificationResult,
) {
    if !layout.html {
        return;
    }
    match capture_regular_file(
        &directory.join(ASSESSMENT_HTML_NAME),
        MAX_COMPARISON_INPUT_BYTES,
        FixedFile::Html,
        hook,
    ) {
        Ok(capture) => {
            let (length_matches, digest_matches) =
                record_file_measurement(&capture, expected, &mut result.checks.assessment_html);
            record_measurement_mismatches(length_matches, digest_matches, result);
            let utf8 = if std::str::from_utf8(&capture.bytes).is_ok() {
                CheckState::CheckedMatched
            } else {
                result.reject(ReasonCode::HtmlInvalidUtf8);
                CheckState::CheckedMismatched
            };
            result.checks.assessment_html.utf8 = Some(utf8);
            if utf8 == CheckState::CheckedMismatched {
                result.checks.assessment_html.state = CheckState::CheckedMismatched;
            }
        },
        Err(error) => {
            result.checks.assessment_html.state = CheckState::NotChecked;
            record_capture_error(error, false, result);
        },
    }
}

fn verify_json_payload(
    directory: &Path,
    layout: &Layout,
    expected: &ExpectedFile,
    hook: &mut impl VerificationHook,
    result: &mut VerificationResult,
) -> Option<Vec<u8>> {
    if !layout.json {
        return None;
    }
    match capture_regular_file(
        &directory.join(ASSESSMENT_JSON_NAME),
        MAX_COMPARISON_INPUT_BYTES,
        FixedFile::Json,
        hook,
    ) {
        Ok(capture) => {
            let (length_matches, digest_matches) =
                record_file_measurement(&capture, expected, &mut result.checks.assessment_json);
            record_measurement_mismatches(length_matches, digest_matches, result);
            Some(capture.bytes)
        },
        Err(error) => {
            result.checks.assessment_json.state = CheckState::NotChecked;
            record_capture_error(error, false, result);
            None
        },
    }
}

fn record_file_measurement(
    capture: &CapturedFile,
    expected: &ExpectedFile,
    check: &mut FileCheck,
) -> (bool, bool) {
    check.observed_byte_length = Some(capture.byte_length);
    check.observed_sha256 = Some(capture.sha256.clone());
    let length_matches = capture.byte_length == expected.byte_length;
    let digest_matches = capture.sha256 == expected.sha256;
    check.state = if length_matches && digest_matches {
        CheckState::CheckedMatched
    } else {
        CheckState::CheckedMismatched
    };
    (length_matches, digest_matches)
}

fn record_measurement_mismatches(
    length_matches: bool,
    digest_matches: bool,
    result: &mut VerificationResult,
) {
    if !length_matches {
        result.reject(ReasonCode::PayloadLengthMismatch);
    }
    if !digest_matches {
        result.reject(ReasonCode::PayloadDigestMismatch);
    }
}

fn record_capture_error(error: CaptureError, manifest: bool, result: &mut VerificationResult) {
    result.reject(match error {
        CaptureError::Unavailable if manifest => ReasonCode::ManifestUnavailable,
        CaptureError::Unavailable => ReasonCode::PayloadUnavailable,
        CaptureError::TooLarge if manifest => ReasonCode::ManifestTooLarge,
        CaptureError::TooLarge => ReasonCode::PayloadTooLarge,
        CaptureError::Changed => ReasonCode::ConcurrentChangeObserved,
    });
}

fn render_result(
    result: &VerificationResult,
    format: CliVerificationFormat,
) -> Result<String, ReportVerifyError> {
    let mut rendered = match format {
        CliVerificationFormat::Json => {
            serde_json::to_string_pretty(result).map_err(|_| ReportVerifyError::EncodingFailed)?
        },
        CliVerificationFormat::Text => render_text(result),
    };
    rendered.push('\n');
    if rendered.len() > MAX_VERIFICATION_OUTPUT_BYTES {
        return Err(ReportVerifyError::LimitExceeded);
    }
    Ok(rendered)
}

fn render_text(result: &VerificationResult) -> String {
    let mut output = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(output, "Termivar report bundle verification");
    let _ = writeln!(output, "status: {}", status_name(result.status));
    if !result.reason_codes.is_empty() {
        let reasons = result
            .reason_codes
            .iter()
            .map(|reason| reason_name(*reason))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(output, "reason_codes: {reasons}");
    }
    if let Some(digest) = &result.manifest.sha256 {
        let _ = writeln!(output, "manifest_sha256: {digest}");
    }
    let _ = writeln!(output, "checks:");
    let _ = writeln!(output, "  layout: {}", check_name(result.checks.layout));
    let _ = writeln!(output, "  manifest: {}", check_name(result.checks.manifest));
    write_file_check(&mut output, &result.checks.assessment_html);
    write_file_check(&mut output, &result.checks.assessment_json);
    let _ = writeln!(
        output,
        "  assessment_document: {}",
        check_name(result.checks.assessment_document)
    );
    let _ = writeln!(
        output,
        "  assessment_summary: {}",
        check_name(result.checks.assessment_summary)
    );
    let _ = writeln!(output, "limits:");
    let _ = writeln!(output, "  producer/source authenticity: not established");
    let _ = writeln!(
        output,
        "  HTML equivalence or executable safety: not established"
    );
    let _ = writeln!(
        output,
        "  original scan scope, findings, and remediation: not evaluated"
    );
    let _ = writeln!(
        output,
        "  later filesystem state: not established; result describes bytes read during this invocation"
    );
    output
}

fn write_file_check(output: &mut String, check: &FileCheck) {
    use std::fmt::Write as _;
    let _ = writeln!(output, "  {}: {}", check.name, check_name(check.state));
    if let (Some(expected), Some(observed)) =
        (check.expected_byte_length, check.observed_byte_length)
    {
        let _ = writeln!(output, "    bytes: expected={expected} observed={observed}");
    }
    if let (Some(expected), Some(observed)) = (&check.expected_sha256, &check.observed_sha256) {
        let _ = writeln!(
            output,
            "    sha256: expected={expected} observed={observed}"
        );
    }
    if let Some(utf8) = check.utf8 {
        let _ = writeln!(output, "    utf8: {}", check_name(utf8));
    }
}

fn status_name(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::IntegrityMatch => "integrity_match",
        VerificationStatus::NotVerified => "not_verified",
    }
}

fn check_name(state: CheckState) -> &'static str {
    match state {
        CheckState::CheckedMatched => "checked_matched",
        CheckState::CheckedMismatched => "checked_mismatched",
        CheckState::NotChecked => "not_checked",
    }
}

fn reason_name(reason: ReasonCode) -> &'static str {
    match reason {
        ReasonCode::AssessmentAmbiguousIdentity => "assessment_ambiguous_identity",
        ReasonCode::AssessmentInvalidDocument => "assessment_invalid_document",
        ReasonCode::AssessmentInvalidJson => "assessment_invalid_json",
        ReasonCode::AssessmentSummaryMismatch => "assessment_summary_mismatch",
        ReasonCode::AssessmentUnsupportedDocument => "assessment_unsupported_document",
        ReasonCode::ConcurrentChangeObserved => "concurrent_change_observed",
        ReasonCode::DirectoryUnavailable => "directory_unavailable",
        ReasonCode::HtmlInvalidUtf8 => "html_invalid_utf8",
        ReasonCode::InvalidManifest => "invalid_manifest",
        ReasonCode::InvalidManifestContract => "invalid_manifest_contract",
        ReasonCode::ManifestTooLarge => "manifest_too_large",
        ReasonCode::ManifestUnavailable => "manifest_unavailable",
        ReasonCode::MissingAssessmentHtml => "missing_assessment_html",
        ReasonCode::MissingAssessmentJson => "missing_assessment_json",
        ReasonCode::MissingManifest => "missing_manifest",
        ReasonCode::PayloadDigestMismatch => "payload_digest_mismatch",
        ReasonCode::PayloadLengthMismatch => "payload_length_mismatch",
        ReasonCode::PayloadTooLarge => "payload_too_large",
        ReasonCode::PayloadUnavailable => "payload_unavailable",
        ReasonCode::UnsupportedManifestSchema => "unsupported_manifest_schema",
        ReasonCode::UnsupportedPath => "unsupported_path",
        ReasonCode::UnexpectedLayout => "unexpected_layout",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::{json, Value};
    use std::{collections::BTreeMap, ffi::OsString, fs, time::SystemTime};

    const EMPTY_ASSESSMENT: &[u8] = br#"{
  "schema": "venom-rendered-assessment/v1",
  "source_schema": "venom-assessment-run/v1",
  "run_schema": "venom-run/v1",
  "profile_schema": "venom.scan-profile/v1",
  "profile": "web-review",
  "status": "complete",
  "subject_count": 1,
  "item_count": 0,
  "items": []
}"#;

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn manifest_value(
        html: &[u8],
        assessment: &[u8],
        subject_count: u64,
        item_count: u64,
    ) -> Value {
        json!({
            "schema": REPORT_BUNDLE_SCHEMA,
            "producer": {
                "product": EXPECTED_PRODUCT,
                "version": "0.10.0-alpha.2"
            },
            "assessment": {
                "profile": EXPECTED_PROFILE,
                "status": EXPECTED_STATUS,
                "subject_count": subject_count,
                "item_count": item_count
            },
            "files": [
                {
                    "name": ASSESSMENT_HTML_NAME,
                    "format": "html",
                    "media_type": "text/html; charset=utf-8",
                    "byte_length": html.len(),
                    "sha256": digest(html)
                },
                {
                    "name": ASSESSMENT_JSON_NAME,
                    "format": "json",
                    "media_type": "application/json",
                    "byte_length": assessment.len(),
                    "sha256": digest(assessment)
                }
            ]
        })
    }

    fn manifest_bytes(
        html: &[u8],
        assessment: &[u8],
        subject_count: u64,
        item_count: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&manifest_value(html, assessment, subject_count, item_count)).unwrap()
    }

    fn write_bundle(
        path: &Path,
        html: &[u8],
        assessment: &[u8],
        subject_count: u64,
        item_count: u64,
    ) {
        fs::create_dir(path).unwrap();
        fs::write(path.join(ASSESSMENT_HTML_NAME), html).unwrap();
        fs::write(path.join(ASSESSMENT_JSON_NAME), assessment).unwrap();
        fs::write(
            path.join(MANIFEST_NAME),
            manifest_bytes(html, assessment, subject_count, item_count),
        )
        .unwrap();
    }

    fn committed_bundle() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/examples/report-bundle/assessment-001")
    }

    fn copy_committed_bundle(destination: &Path) {
        fs::create_dir(destination).unwrap();
        for name in [ASSESSMENT_HTML_NAME, ASSESSMENT_JSON_NAME, MANIFEST_NAME] {
            fs::copy(committed_bundle().join(name), destination.join(name)).unwrap();
        }
    }

    fn snapshot(path: &Path) -> BTreeMap<OsString, (Vec<u8>, u64, bool, Option<SystemTime>)> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                (
                    entry.file_name(),
                    (
                        fs::read(entry.path()).unwrap(),
                        metadata.len(),
                        metadata.permissions().readonly(),
                        metadata.modified().ok(),
                    ),
                )
            })
            .collect()
    }

    fn has_reason(result: &VerificationResult, reason: ReasonCode) -> bool {
        result.reason_codes.contains(&reason)
    }

    #[test]
    fn cli_uses_exact_dir_spelling_and_two_formats() {
        for (format, expected) in [
            (None, CliVerificationFormat::Text),
            (Some("text"), CliVerificationFormat::Text),
            (Some("json"), CliVerificationFormat::Json),
        ] {
            let mut argv = vec!["termivar", "report", "verify", "--dir", "bundle"];
            if let Some(format) = format {
                argv.extend(["--format", format]);
            }
            let cli = crate::Cli::try_parse_from(argv).unwrap();
            let Some(crate::Commands::Report {
                command: crate::report_compare::ReportCommands::Verify(args),
            }) = cli.command
            else {
                panic!("expected report verify command");
            };
            assert_eq!(args.directory, Path::new("bundle"));
            assert_eq!(args.format, expected);
        }
        for argv in [
            vec!["termivar", "report", "verify"],
            vec!["termivar", "report", "verify", "--directory", "bundle"],
            vec![
                "termivar", "report", "verify", "--dir", "bundle", "--format", "html",
            ],
            vec![
                "termivar",
                "report",
                "verify",
                "--dir",
                "bundle",
                "--output",
                "result.json",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn strict_manifest_accepts_order_independence_and_known_sha256() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let html = b"<!doctype html><title>fixture</title>";
        let mut value = manifest_value(html, EMPTY_ASSESSMENT, 1, 0);
        value["files"].as_array_mut().unwrap().reverse();
        let parsed = parse_manifest(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed.html.byte_length, html.len() as u64);
        assert_eq!(parsed.html.sha256, digest(html));
        assert_eq!(parsed.json.byte_length, EMPTY_ASSESSMENT.len() as u64);
        assert_eq!(parsed.subject_count, 1);
        assert_eq!(parsed.item_count, 0);
    }

    #[test]
    fn strict_manifest_rejects_duplicate_and_unknown_fields_at_every_level() {
        let compact = String::from_utf8(manifest_bytes(b"html", EMPTY_ASSESSMENT, 1, 0)).unwrap();
        for duplicate in [
            compact.replacen(
                &format!("\"schema\":\"{REPORT_BUNDLE_SCHEMA}\""),
                &format!(
                    "\"schema\":\"{REPORT_BUNDLE_SCHEMA}\",\"schema\":\"{REPORT_BUNDLE_SCHEMA}\""
                ),
                1,
            ),
            compact.replacen(
                "\"product\":\"Termivar\"",
                "\"product\":\"Termivar\",\"product\":\"Termivar\"",
                1,
            ),
            compact.replacen(
                "\"profile\":\"web-review\"",
                "\"profile\":\"web-review\",\"profile\":\"web-review\"",
                1,
            ),
            compact.replacen(
                "\"name\":\"assessment.html\"",
                "\"name\":\"assessment.html\",\"name\":\"assessment.html\"",
                1,
            ),
        ] {
            assert_eq!(
                parse_manifest(duplicate.as_bytes()).err().unwrap(),
                ManifestError::Invalid
            );
        }

        for path in [
            vec![],
            vec!["producer"],
            vec!["assessment"],
            vec!["files", "0"],
        ] {
            let mut value = manifest_value(b"html", EMPTY_ASSESSMENT, 1, 0);
            let object = match path.as_slice() {
                [] => value.as_object_mut().unwrap(),
                ["producer"] => value["producer"].as_object_mut().unwrap(),
                ["assessment"] => value["assessment"].as_object_mut().unwrap(),
                ["files", "0"] => value["files"][0].as_object_mut().unwrap(),
                _ => unreachable!(),
            };
            object.insert("unexpected".to_owned(), json!(true));
            assert_eq!(
                parse_manifest(&serde_json::to_vec(&value).unwrap())
                    .err()
                    .unwrap(),
                ManifestError::Invalid
            );
        }
    }

    #[test]
    fn strict_manifest_rejects_schema_types_limits_digests_and_path_like_names() {
        let base = manifest_value(b"html", EMPTY_ASSESSMENT, 1, 0);
        let mut cases = Vec::new();
        for replacement in [json!(null), json!(-1), json!(1.5), json!("1")] {
            let mut value = base.clone();
            value["assessment"]["item_count"] = replacement;
            cases.push((value, ManifestError::Invalid));
        }
        for (pointer, replacement) in [
            ("/producer/product", json!("Other")),
            ("/producer/version", json!("not a version")),
            ("/assessment/profile", json!("baseline")),
            ("/assessment/status", json!("partial")),
            ("/assessment/subject_count", json!(0)),
            ("/assessment/subject_count", json!(MAX_SUBJECT_COUNT + 1)),
            ("/assessment/item_count", json!(MAX_ITEM_COUNT + 1)),
            ("/files/0/byte_length", json!(0)),
            (
                "/files/0/byte_length",
                json!(MAX_COMPARISON_INPUT_BYTES as u64 + 1),
            ),
            ("/files/0/sha256", json!("A".repeat(64))),
            ("/files/0/sha256", json!("0".repeat(63))),
            ("/files/0/name", json!(MANIFEST_NAME)),
            ("/files/0/name", json!("../assessment.html")),
            ("/files/0/name", json!("C:\\assessment.html")),
            ("/files/0/name", json!("https://example.test/report")),
            ("/files/0/media_type", json!("text/html")),
            ("/files/1/format", json!("html")),
        ] {
            let mut value = base.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            cases.push((value, ManifestError::InvalidContract));
        }
        let mut duplicate = base.clone();
        duplicate["files"][1] = duplicate["files"][0].clone();
        cases.push((duplicate, ManifestError::InvalidContract));
        let mut wrong_schema = base.clone();
        wrong_schema["schema"] = json!("termivar-report-bundle/v2");
        cases.push((wrong_schema, ManifestError::UnsupportedSchema));
        let mut long_version = base;
        long_version["producer"]["version"] = json!("1".repeat(MAX_VERSION_BYTES + 1));
        cases.push((long_version, ManifestError::InvalidContract));

        for (value, expected) in cases {
            assert_eq!(
                parse_manifest(&serde_json::to_vec(&value).unwrap())
                    .err()
                    .unwrap(),
                expected,
                "{value}"
            );
        }
        assert_eq!(
            parse_manifest(&vec![b' '; MAX_MANIFEST_BYTES + 1])
                .err()
                .unwrap(),
            ManifestError::Invalid
        );
        for file_count in [0, 1, 3] {
            let mut value = manifest_value(b"html", EMPTY_ASSESSMENT, 1, 0);
            value["files"] = Value::Array(
                value["files"].as_array().unwrap()[..file_count.min(2)]
                    .iter()
                    .cloned()
                    .chain((2..file_count).map(|_| json!({})))
                    .collect(),
            );
            assert_eq!(
                parse_manifest(&serde_json::to_vec(&value).unwrap())
                    .err()
                    .unwrap(),
                ManifestError::Invalid
            );
        }
        assert_eq!(
            parse_manifest(&[0xff]).err().unwrap(),
            ManifestError::Invalid
        );
    }

    #[test]
    fn committed_bundle_verifies_without_modifying_any_content_or_names() {
        let path = committed_bundle();
        let before = snapshot(&path);
        let result = verify_directory(&path);
        let after = snapshot(&path);
        assert!(result.is_match(), "{:?}", result.reason_codes);
        assert_eq!(result.status, VerificationStatus::IntegrityMatch);
        assert_eq!(result.checks.layout, CheckState::CheckedMatched);
        assert_eq!(result.checks.manifest, CheckState::CheckedMatched);
        assert_eq!(
            result.checks.assessment_html.state,
            CheckState::CheckedMatched
        );
        assert_eq!(
            result.checks.assessment_html.utf8,
            Some(CheckState::CheckedMatched)
        );
        assert_eq!(
            result.checks.assessment_json.state,
            CheckState::CheckedMatched
        );
        assert_eq!(
            result.checks.assessment_document,
            CheckState::CheckedMatched
        );
        assert_eq!(result.checks.assessment_summary, CheckState::CheckedMatched);
        assert_eq!(result.manifest.subject_count, Some(1));
        assert_eq!(result.manifest.item_count, Some(4));
        assert_eq!(before, after, "verification changed the reference bundle");
    }

    #[test]
    fn missing_and_unexpected_layouts_are_distinct_and_never_repaired() {
        for (missing, reason) in [
            (MANIFEST_NAME, ReasonCode::MissingManifest),
            (ASSESSMENT_HTML_NAME, ReasonCode::MissingAssessmentHtml),
            (ASSESSMENT_JSON_NAME, ReasonCode::MissingAssessmentJson),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let bundle = parent.path().join("bundle");
            copy_committed_bundle(&bundle);
            fs::remove_file(bundle.join(missing)).unwrap();
            let before = snapshot(&bundle);
            let result = verify_directory(&bundle);
            assert!(!result.is_match());
            assert!(has_reason(&result, reason));
            assert_eq!(result.checks.layout, CheckState::CheckedMismatched);
            if missing == MANIFEST_NAME {
                assert_eq!(result.checks.manifest, CheckState::NotChecked);
                assert_eq!(result.checks.assessment_html.state, CheckState::NotChecked);
                assert_eq!(result.checks.assessment_json.state, CheckState::NotChecked);
            }
            assert_eq!(before, snapshot(&bundle));
        }

        for child_directory in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let bundle = parent.path().join("bundle");
            copy_committed_bundle(&bundle);
            let extra = bundle.join("PRIVATE-unexpected");
            if child_directory {
                fs::create_dir(&extra).unwrap();
            } else {
                fs::write(&extra, b"not inspected").unwrap();
            }
            let first = verify_directory(&bundle);
            let second = verify_directory(&bundle);
            assert!(!first.is_match());
            assert!(has_reason(&first, ReasonCode::UnexpectedLayout));
            for false_reason in [
                ReasonCode::MissingManifest,
                ReasonCode::MissingAssessmentHtml,
                ReasonCode::MissingAssessmentJson,
                ReasonCode::ConcurrentChangeObserved,
            ] {
                assert!(
                    !has_reason(&first, false_reason),
                    "early bounded enumeration must not claim an unobserved absence"
                );
            }
            assert_eq!(first.reason_codes, second.reason_codes);
            assert_eq!(first.checks.manifest, CheckState::NotChecked);
            assert_eq!(first.checks.assessment_html.state, CheckState::NotChecked);
            assert_eq!(first.checks.assessment_json.state, CheckState::NotChecked);
            assert!(extra.exists(), "verifier removed an unexpected entry");
        }
    }

    #[test]
    fn exact_byte_integrity_distinguishes_digest_length_and_utf8_failures() {
        let parent = tempfile::tempdir().unwrap();

        let same_length = parent.path().join("same-length");
        copy_committed_bundle(&same_length);
        let html_path = same_length.join(ASSESSMENT_HTML_NAME);
        let mut html = fs::read(&html_path).unwrap();
        html[0] ^= 1;
        fs::write(&html_path, html).unwrap();
        let result = verify_directory(&same_length);
        assert!(has_reason(&result, ReasonCode::PayloadDigestMismatch));
        assert!(!has_reason(&result, ReasonCode::PayloadLengthMismatch));
        assert_eq!(
            result.checks.assessment_html.state,
            CheckState::CheckedMismatched
        );

        let changed_length = parent.path().join("changed-length");
        copy_committed_bundle(&changed_length);
        let json_path = changed_length.join(ASSESSMENT_JSON_NAME);
        let mut json = fs::read(&json_path).unwrap();
        json.push(b' ');
        fs::write(json_path, json).unwrap();
        let result = verify_directory(&changed_length);
        assert!(has_reason(&result, ReasonCode::PayloadLengthMismatch));
        assert!(has_reason(&result, ReasonCode::PayloadDigestMismatch));

        let invalid_utf8 = parent.path().join("invalid-utf8");
        write_bundle(&invalid_utf8, &[0xff], EMPTY_ASSESSMENT, 1, 0);
        let result = verify_directory(&invalid_utf8);
        assert!(has_reason(&result, ReasonCode::HtmlInvalidUtf8));
        assert_eq!(
            result.checks.assessment_html.utf8,
            Some(CheckState::CheckedMismatched)
        );
        assert_eq!(
            result.checks.assessment_json.state,
            CheckState::CheckedMatched
        );
    }

    #[test]
    fn assessment_validation_and_manifest_summary_are_independent_checks() {
        let parent = tempfile::tempdir().unwrap();
        let inconsistent = parent.path().join("inconsistent");
        write_bundle(
            &inconsistent,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            2,
            0,
        );
        let result = verify_directory(&inconsistent);
        assert_eq!(
            result.checks.assessment_json.state,
            CheckState::CheckedMatched
        );
        assert_eq!(
            result.checks.assessment_document,
            CheckState::CheckedMatched
        );
        assert_eq!(
            result.checks.assessment_summary,
            CheckState::CheckedMismatched
        );
        assert!(has_reason(&result, ReasonCode::AssessmentSummaryMismatch));

        let unsupported = parent.path().join("unsupported");
        let diagnostic = br#"{"schema":"decision-scan/v1"}"#;
        write_bundle(
            &unsupported,
            b"<!doctype html><p>synthetic</p>",
            diagnostic,
            1,
            0,
        );
        let result = verify_directory(&unsupported);
        assert_eq!(
            result.checks.assessment_json.state,
            CheckState::CheckedMatched
        );
        assert_eq!(
            result.checks.assessment_document,
            CheckState::CheckedMismatched
        );
        assert_eq!(result.checks.assessment_summary, CheckState::NotChecked);
        assert!(has_reason(
            &result,
            ReasonCode::AssessmentUnsupportedDocument
        ));

        let malformed = parent.path().join("malformed");
        write_bundle(&malformed, b"<!doctype html><p>synthetic</p>", b"{", 1, 0);
        let result = verify_directory(&malformed);
        assert!(has_reason(&result, ReasonCode::AssessmentInvalidJson));
        assert_eq!(result.checks.assessment_summary, CheckState::NotChecked);
    }

    #[test]
    fn empty_completed_report_and_supported_optional_audit_pass() {
        let mut assessment: Value = serde_json::from_slice(EMPTY_ASSESSMENT).unwrap();
        assessment["openapi_review"] = json!({
            "schema": "security.openapi-review-audit/v1",
            "capability_id": "api.openapi-contract-observed@1",
            "outcome": "not_eligible",
            "candidate_source": "conventional_openapi_json",
            "request_count": 0,
            "active_verification_count": 0,
            "version": null,
            "semantic_digest": null,
            "path_count": 0,
            "operation_count": 0,
            "get_operation_count": 0,
            "write_operation_count": 0,
            "path_parameter_count": 0,
            "query_parameter_count": 0,
            "explicit_auth_operation_count": 0,
            "anonymous_operation_count": 0,
            "url_like_operation_count": 0,
            "multipart_operation_count": 0,
            "deprecated_operation_count": 0,
            "replay_matched": false,
            "item_projected": false
        });
        let bytes = serde_json::to_vec(&assessment).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let bundle = parent.path().join("bundle");
        write_bundle(
            &bundle,
            b"<!doctype html><p>No observations asserted safe.</p>",
            &bytes,
            1,
            0,
        );
        let result = verify_directory(&bundle);
        assert!(result.is_match(), "{:?}", result.reason_codes);
        assert_eq!(result.manifest.item_count, Some(0));
    }

    #[test]
    fn internally_consistent_modified_bytes_do_not_upgrade_the_trust_model() {
        let parent = tempfile::tempdir().unwrap();
        let bundle = parent.path().join("bundle");
        let html = b"<!doctype html><script>INERT-TEST-MARKER</script>";
        write_bundle(&bundle, html, EMPTY_ASSESSMENT, 1, 0);
        let result = verify_directory(&bundle);
        assert!(result.is_match());
        assert_eq!(result.trust.producer_source_authenticity, "not_established");
        assert_eq!(
            result.trust.html_content_equivalence_or_executable_safety,
            "not_established"
        );
        assert_eq!(
            result.trust.original_scan_scope_findings_and_remediation,
            "not_evaluated"
        );
        let rendered = render_result(&result, CliVerificationFormat::Json).unwrap();
        assert!(rendered.contains("\"status\": \"integrity_match\""));
        assert!(rendered.contains("\"producer_source_authenticity\": \"not_established\""));
        assert!(!rendered.contains("INERT-TEST-MARKER"));
    }

    #[test]
    fn manifest_capture_failure_is_not_misreported_as_a_completed_check() {
        let mut result = VerificationResult::new();
        record_capture_error(CaptureError::Unavailable, true, &mut result);
        assert_eq!(result.checks.manifest, CheckState::NotChecked);
        assert!(has_reason(&result, ReasonCode::ManifestUnavailable));

        let parent = tempfile::tempdir().unwrap();
        let bundle = parent.path().join("bundle");
        write_bundle(
            &bundle,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            1,
            0,
        );
        fs::File::create(bundle.join(MANIFEST_NAME))
            .unwrap()
            .set_len((MAX_MANIFEST_BYTES + 1) as u64)
            .unwrap();
        let result = verify_directory(&bundle);
        assert_eq!(result.checks.manifest, CheckState::NotChecked);
        assert!(has_reason(&result, ReasonCode::ManifestTooLarge));
        assert_eq!(result.checks.assessment_html.state, CheckState::NotChecked);
        assert_eq!(result.checks.assessment_json.state, CheckState::NotChecked);
    }

    #[test]
    fn captured_manifest_errors_and_unread_payloads_keep_distinct_check_states() {
        let parent = tempfile::tempdir().unwrap();
        let malformed = parent.path().join("malformed-manifest");
        write_bundle(
            &malformed,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            1,
            0,
        );
        fs::write(malformed.join(MANIFEST_NAME), b"{\"schema\":").unwrap();
        let result = verify_directory(&malformed);
        assert_eq!(result.checks.manifest, CheckState::CheckedMismatched);
        assert!(has_reason(&result, ReasonCode::InvalidManifest));
        assert_eq!(result.checks.assessment_html.state, CheckState::NotChecked);
        assert_eq!(result.checks.assessment_json.state, CheckState::NotChecked);

        let oversized = parent.path().join("oversized-html");
        write_bundle(&oversized, b"x", EMPTY_ASSESSMENT, 1, 0);
        fs::File::create(oversized.join(ASSESSMENT_HTML_NAME))
            .unwrap()
            .set_len((MAX_COMPARISON_INPUT_BYTES + 1) as u64)
            .unwrap();
        let result = verify_directory(&oversized);
        assert_eq!(result.checks.manifest, CheckState::CheckedMatched);
        assert_eq!(result.checks.assessment_html.state, CheckState::NotChecked);
        assert!(has_reason(&result, ReasonCode::PayloadTooLarge));

        let invalid_json_utf8 = parent.path().join("invalid-json-utf8");
        write_bundle(
            &invalid_json_utf8,
            b"<!doctype html><p>synthetic</p>",
            &[0xff],
            1,
            0,
        );
        let result = verify_directory(&invalid_json_utf8);
        assert_eq!(
            result.checks.assessment_json.state,
            CheckState::CheckedMatched
        );
        assert_eq!(
            result.checks.assessment_document,
            CheckState::CheckedMismatched
        );
        assert!(has_reason(&result, ReasonCode::AssessmentInvalidJson));
    }

    #[test]
    fn fully_read_manifest_failures_map_to_specific_static_reasons() {
        for (name, mutate, reason) in [
            (
                "unsupported-schema",
                (|value: &mut Value| {
                    value["schema"] = json!("termivar-report-bundle/v2");
                }) as fn(&mut Value),
                ReasonCode::UnsupportedManifestSchema,
            ),
            (
                "invalid-contract",
                (|value: &mut Value| {
                    value["producer"]["product"] = json!("PRIVATE-OTHER-PRODUCT");
                }) as fn(&mut Value),
                ReasonCode::InvalidManifestContract,
            ),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let bundle = parent.path().join(name);
            write_bundle(
                &bundle,
                b"<!doctype html><p>synthetic</p>",
                EMPTY_ASSESSMENT,
                1,
                0,
            );
            let mut manifest: Value =
                serde_json::from_slice(&fs::read(bundle.join(MANIFEST_NAME)).unwrap()).unwrap();
            mutate(&mut manifest);
            fs::write(
                bundle.join(MANIFEST_NAME),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let result = verify_directory(&bundle);
            assert_eq!(result.checks.manifest, CheckState::CheckedMismatched);
            assert!(has_reason(&result, reason));
            let rendered = render_result(&result, CliVerificationFormat::Json).unwrap();
            assert!(!rendered.contains("PRIVATE"));
        }
    }

    struct GrowAfterRead {
        kind: FixedFile,
        path: PathBuf,
    }

    impl VerificationHook for GrowAfterRead {
        fn after_read(&mut self, kind: FixedFile) {
            if kind == self.kind {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&self.path)
                    .unwrap()
                    .write_all(b"x")
                    .unwrap();
            }
        }
    }

    struct AddBeforeFinalLayout {
        path: PathBuf,
    }

    impl VerificationHook for AddBeforeFinalLayout {
        fn before_final_layout(&mut self) {
            fs::write(&self.path, b"residual").unwrap();
        }
    }

    #[test]
    fn deterministic_hooks_detect_growth_and_entry_set_changes() {
        let parent = tempfile::tempdir().unwrap();
        let growing = parent.path().join("growing");
        write_bundle(
            &growing,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            1,
            0,
        );
        let mut hook = GrowAfterRead {
            kind: FixedFile::Html,
            path: growing.join(ASSESSMENT_HTML_NAME),
        };
        let result = verify_directory_with(&growing, &mut hook);
        assert!(has_reason(&result, ReasonCode::ConcurrentChangeObserved));
        assert_eq!(result.checks.assessment_html.state, CheckState::NotChecked);

        let changing_layout = parent.path().join("changing-layout");
        write_bundle(
            &changing_layout,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            1,
            0,
        );
        let added = changing_layout.join("late-temp");
        let mut hook = AddBeforeFinalLayout {
            path: added.clone(),
        };
        let result = verify_directory_with(&changing_layout, &mut hook);
        assert!(has_reason(&result, ReasonCode::ConcurrentChangeObserved));
        assert_eq!(result.checks.layout, CheckState::CheckedMismatched);
        assert_eq!(fs::read(added).unwrap(), b"residual");
    }

    #[cfg(unix)]
    #[test]
    fn link_directories_and_payloads_are_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        write_bundle(
            &real,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            1,
            0,
        );
        let linked = parent.path().join("linked");
        symlink(&real, &linked).unwrap();
        let result = verify_directory(&linked);
        assert!(has_reason(&result, ReasonCode::DirectoryUnavailable));

        let foreign = parent.path().join("foreign.html");
        fs::write(&foreign, b"<!doctype html><p>foreign</p>").unwrap();
        fs::remove_file(real.join(ASSESSMENT_HTML_NAME)).unwrap();
        symlink(&foreign, real.join(ASSESSMENT_HTML_NAME)).unwrap();
        let result = verify_directory(&real);
        assert!(has_reason(&result, ReasonCode::UnexpectedLayout));
        assert_eq!(fs::read(foreign).unwrap(), b"<!doctype html><p>foreign</p>");
    }

    #[cfg(windows)]
    #[test]
    fn directory_reparse_point_is_rejected_without_symlink_privilege() {
        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        write_bundle(
            &real,
            b"<!doctype html><p>synthetic</p>",
            EMPTY_ASSESSMENT,
            1,
            0,
        );
        let linked = parent.path().join("linked");
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&linked)
            .arg(&real)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let result = verify_directory(&linked);
        assert!(has_reason(&result, ReasonCode::DirectoryUnavailable));
    }

    #[test]
    fn unsupported_paths_and_rendering_are_bounded_deterministic_and_redacted() {
        for path in [
            "-",
            "https://example.test/PRIVATE-bundle",
            r"\\server\share\PRIVATE-bundle",
            r"\\.\pipe\PRIVATE-bundle",
        ] {
            let result = verify_directory(Path::new(path));
            assert!(has_reason(&result, ReasonCode::UnsupportedPath));
            let rendered = render_result(&result, CliVerificationFormat::Json).unwrap();
            assert!(!rendered.contains("PRIVATE"));
        }

        let result = verify_directory(&committed_bundle());
        let first = render_result(&result, CliVerificationFormat::Json).unwrap();
        let second = render_result(&result, CliVerificationFormat::Json).unwrap();
        assert_eq!(first, second);
        assert!(first.len() <= MAX_VERIFICATION_OUTPUT_BYTES);
        let document: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(document["schema"], VERIFICATION_SCHEMA);
        assert_eq!(document["status"], "integrity_match");
        assert_eq!(document["checks"]["layout"], "checked_matched");
        let text = render_result(&result, CliVerificationFormat::Text).unwrap();
        assert!(text.starts_with("Termivar report bundle verification\n"));
        assert!(text.contains("producer/source authenticity: not established"));
        assert!(text.contains("HTML equivalence or executable safety: not established"));
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("PRIVATE-WRITER-FAILURE"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_seam_preserves_exact_result_exit_and_output_failure_semantics() {
        let mut success = Vec::new();
        let exit = run_with_writer(
            ReportVerifyArgs {
                directory: committed_bundle(),
                format: CliVerificationFormat::Json,
            },
            &mut success,
        )
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        let document: Value = serde_json::from_slice(&success).unwrap();
        assert_eq!(document["status"], "integrity_match");

        let parent = tempfile::tempdir().unwrap();
        let incomplete = parent.path().join("incomplete");
        fs::create_dir(&incomplete).unwrap();
        let mut failure = Vec::new();
        let exit = run_with_writer(
            ReportVerifyArgs {
                directory: incomplete,
                format: CliVerificationFormat::Json,
            },
            &mut failure,
        )
        .unwrap();
        assert_eq!(exit, ExitCode::FAILURE);
        let document: Value = serde_json::from_slice(&failure).unwrap();
        assert_eq!(document["status"], "not_verified");
        assert_eq!(document["checks"]["manifest"], "not_checked");

        let error = run_with_writer(
            ReportVerifyArgs {
                directory: committed_bundle(),
                format: CliVerificationFormat::Text,
            },
            &mut FailingWriter,
        )
        .unwrap_err();
        assert_eq!(error, ReportVerifyError::WriteFailed);
        assert!(!error.to_string().contains("PRIVATE"));
    }

    #[test]
    fn result_renderer_enforces_its_independent_byte_ceiling() {
        let mut result = VerificationResult::new();
        let oversized = "0".repeat(MAX_VERIFICATION_OUTPUT_BYTES);
        result.checks.assessment_html.expected_sha256 = Some(oversized.clone());
        result.checks.assessment_html.observed_sha256 = Some(oversized);
        assert_eq!(
            render_result(&result, CliVerificationFormat::Json).unwrap_err(),
            ReportVerifyError::LimitExceeded
        );
        assert_eq!(
            render_result(&result, CliVerificationFormat::Text).unwrap_err(),
            ReportVerifyError::LimitExceeded
        );
    }
}
