use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CICDPipeline {
    pub id: String,
    pub name: String,
    pub workflows: Vec<WorkflowJob>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowJob {
    pub id: String,
    pub name: String,
    pub job_type: JobType,
    pub status: JobStatus,
    pub triggers: Vec<Trigger>,
    pub steps: Vec<WorkflowStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobType {
    UnitTests,
    IntegrationTests,
    SecurityScanning,
    CodeCoverage,
    PerformanceRegression,
    DependencyCheck,
    ReleaseCandidate,
    Deployment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Skipped,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    pub trigger_type: TriggerType,
    pub branch_filter: Option<String>,
    pub path_filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TriggerType {
    Push,
    PullRequest,
    Schedule,
    Manual,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub sequence: u32,
    pub name: String,
    pub command: String,
    pub timeout_minutes: u32,
    pub status: JobStatus,
    pub output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineExecution {
    pub execution_id: String,
    pub pipeline_id: String,
    pub pipeline_name: String,
    pub trigger: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub jobs: Vec<JobExecution>,
    pub status: PipelineStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PipelineStatus {
    Running,
    Passed,
    Failed,
    PartiallyFailed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecution {
    pub job_id: String,
    pub job_name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status: JobStatus,
    pub duration_seconds: u64,
    pub artifacts: Vec<String>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeCoverageReport {
    pub execution_id: String,
    pub total_lines: u32,
    pub covered_lines: u32,
    pub coverage_percent: f32,
    pub branch_coverage_percent: f32,
    pub uncovered_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanResult {
    pub execution_id: String,
    pub scan_type: String,
    pub vulnerabilities_found: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseCandidate {
    pub release_id: String,
    pub version: String,
    pub commit_sha: String,
    pub created_at: DateTime<Utc>,
    pub all_checks_passed: bool,
    pub changelog: String,
}

impl CICDPipeline {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            workflows: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_workflow(&mut self, workflow: WorkflowJob) {
        self.workflows.push(workflow);
    }

    pub fn with_unit_tests() -> WorkflowJob {
        Self::create_workflow("Run Unit Tests", JobType::UnitTests)
    }

    pub fn with_integration_tests() -> WorkflowJob {
        Self::create_workflow("Run Integration Tests", JobType::IntegrationTests)
    }

    pub fn with_security_scan() -> WorkflowJob {
        Self::create_workflow("Security Scanning", JobType::SecurityScanning)
    }

    pub fn with_code_coverage() -> WorkflowJob {
        Self::create_workflow("Code Coverage Report", JobType::CodeCoverage)
    }

    pub fn with_dependency_check() -> WorkflowJob {
        Self::create_workflow("Dependency Check", JobType::DependencyCheck)
    }

    fn create_workflow(name: &str, job_type: JobType) -> WorkflowJob {
        WorkflowJob {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            job_type,
            status: JobStatus::Pending,
            triggers: Vec::new(),
            steps: Vec::new(),
        }
    }
}

impl WorkflowJob {
    pub fn add_trigger(&mut self, trigger: Trigger) {
        self.triggers.push(trigger);
    }

    pub fn add_step(&mut self, step: WorkflowStep) {
        self.steps.push(step);
    }
}

impl PipelineExecution {
    pub fn new(pipeline_id: String, pipeline_name: String, trigger: String) -> Self {
        Self {
            execution_id: Uuid::new_v4().to_string(),
            pipeline_id,
            pipeline_name,
            trigger,
            start_time: Utc::now(),
            end_time: None,
            jobs: Vec::new(),
            status: PipelineStatus::Running,
        }
    }

    pub fn add_job(&mut self, job: JobExecution) {
        self.jobs.push(job);
    }

    pub fn finish(&mut self) {
        self.end_time = Some(Utc::now());

        let failed_jobs = self.jobs.iter().filter(|j| j.status == JobStatus::Failed).count();
        if failed_jobs > 0 {
            self.status = PipelineStatus::Failed;
        } else {
            self.status = PipelineStatus::Passed;
        }
    }

    pub fn duration_seconds(&self) -> u64 {
        let end = self.end_time.unwrap_or_else(Utc::now);
        (end - self.start_time).num_seconds() as u64
    }

    pub fn all_jobs_passed(&self) -> bool {
        self.jobs.iter().all(|j| j.status == JobStatus::Passed || j.status == JobStatus::Skipped)
    }
}

impl JobExecution {
    pub fn new(job_id: String, job_name: String) -> Self {
        Self {
            job_id,
            job_name,
            start_time: Utc::now(),
            end_time: None,
            status: JobStatus::Running,
            duration_seconds: 0,
            artifacts: Vec::new(),
            logs: Vec::new(),
        }
    }

    pub fn finish(&mut self, status: JobStatus) {
        self.end_time = Some(Utc::now());
        self.status = status;
        self.duration_seconds = (self.end_time.unwrap() - self.start_time).num_seconds() as u64;
    }

    pub fn add_artifact(&mut self, artifact: String) {
        self.artifacts.push(artifact);
    }

    pub fn add_log(&mut self, log: String) {
        self.logs.push(log);
    }
}

impl CodeCoverageReport {
    pub fn new(execution_id: String) -> Self {
        Self {
            execution_id,
            total_lines: 0,
            covered_lines: 0,
            coverage_percent: 0.0,
            branch_coverage_percent: 0.0,
            uncovered_files: Vec::new(),
        }
    }

    pub fn calculate_coverage(&mut self) {
        if self.total_lines > 0 {
            self.coverage_percent = (self.covered_lines as f32 / self.total_lines as f32) * 100.0;
        }
    }

    pub fn is_compliant(&self, min_coverage: f32) -> bool {
        self.coverage_percent >= min_coverage
    }
}

impl SecurityScanResult {
    pub fn new(execution_id: String, scan_type: String) -> Self {
        Self {
            execution_id,
            scan_type,
            vulnerabilities_found: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            passed: true,
        }
    }

    pub fn is_secure(&self) -> bool {
        self.critical_count == 0 && self.high_count == 0
    }
}

impl ReleaseCandidate {
    pub fn new(version: String, commit_sha: String, changelog: String) -> Self {
        Self {
            release_id: Uuid::new_v4().to_string(),
            version,
            commit_sha,
            created_at: Utc::now(),
            all_checks_passed: false,
            changelog,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_cd_pipeline_creation() {
        let mut pipeline = CICDPipeline::new("Main CI Pipeline".to_string());
        let workflow = CICDPipeline::with_unit_tests();
        pipeline.add_workflow(workflow);
        assert_eq!(pipeline.workflows.len(), 1);
    }

    #[test]
    fn test_pipeline_execution() {
        let mut execution = PipelineExecution::new(
            "pipeline_1".to_string(),
            "Main CI".to_string(),
            "push".to_string(),
        );
        let mut job = JobExecution::new("job_1".to_string(), "Unit Tests".to_string());
        job.finish(JobStatus::Passed);
        execution.add_job(job);
        execution.finish();

        assert!(execution.all_jobs_passed());
    }

    #[test]
    fn test_code_coverage_report() {
        let mut report = CodeCoverageReport::new("exec_1".to_string());
        report.total_lines = 1000;
        report.covered_lines = 850;
        report.calculate_coverage();

        assert_eq!(report.coverage_percent, 85.0);
        assert!(report.is_compliant(80.0));
    }
}
