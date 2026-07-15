pub mod report;
pub mod html_generator;
pub mod pdf_generator;

pub use report::{PentestReport, VulnerabilityFinding, RemediationGuidance, ExploitUsed, Recommendation, ReportStatistics, VulnerabilityTemplates};
pub use html_generator::HtmlReportGenerator;
pub use pdf_generator::PdfReportGenerator;
