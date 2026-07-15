// Vulnerability Scoring Engine - CVSS v3.1 + Custom Multi-factor Scoring
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityScore {
    pub id: String,
    pub vuln_type: String,
    pub cvss_score: f64,
    pub cvss_vector: String,
    pub confidence_score: f64,
    pub exploitability_score: f64,
    pub impact_score: f64,
    pub overall_score: f64,
    pub severity: SeverityLevel,
    pub recommendation: String,
    pub factors: Vec<ScoreFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    None,      // 0.0
    Low,       // 0.1-3.9
    Medium,    // 4.0-6.9
    High,      // 7.0-8.9
    Critical,  // 9.0-10.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    pub name: String,
    pub value: f64,
    pub weight: f64,
    pub description: String,
}

pub struct VulnerabilityScorer;

impl VulnerabilityScorer {
    /// Score vulnerability using CVSS v3.1 + custom factors
    pub fn score_vulnerability(
        vuln_type: &str,
        base_metrics: &BaseMetrics,
        temporal_metrics: &TemporalMetrics,
        environmental_metrics: &EnvironmentalMetrics,
    ) -> VulnerabilityScore {
        let cvss_base = Self::calculate_cvss_base(base_metrics);
        let cvss_temporal = Self::calculate_temporal_score(cvss_base, temporal_metrics);
        let cvss_final = Self::calculate_environmental_score(cvss_temporal, environmental_metrics);

        let confidence = Self::calculate_confidence(base_metrics, temporal_metrics);
        let exploitability = Self::calculate_exploitability(base_metrics);
        let impact = Self::calculate_impact(base_metrics);

        let overall = Self::calculate_overall_score(cvss_final, confidence, exploitability);
        let severity = Self::score_to_severity(overall);
        let recommendation = Self::generate_recommendation(&severity, vuln_type);

        let mut factors = Vec::new();
        Self::build_score_factors(&mut factors, base_metrics, temporal_metrics);

        VulnerabilityScore {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: vuln_type.to_string(),
            cvss_score: cvss_final,
            cvss_vector: Self::build_cvss_vector(base_metrics),
            confidence_score: confidence,
            exploitability_score: exploitability,
            impact_score: impact,
            overall_score: overall,
            severity,
            recommendation,
            factors,
        }
    }

    /// Calculate CVSS v3.1 Base Score
    fn calculate_cvss_base(metrics: &BaseMetrics) -> f64 {
        let av_score = Self::score_attack_vector(&metrics.attack_vector);
        let ac_score = Self::score_attack_complexity(&metrics.attack_complexity);
        let pr_score = Self::score_privileges_required(&metrics.privileges_required, &metrics.scope);
        let ui_score = Self::score_user_interaction(&metrics.user_interaction);

        let c_impact = Self::score_confidentiality(&metrics.confidentiality);
        let i_impact = Self::score_integrity(&metrics.integrity);
        let a_impact = Self::score_availability(&metrics.availability);

        let impact = 1.0 - ((1.0 - c_impact) * (1.0 - i_impact) * (1.0 - a_impact));

        if impact == 0.0 {
            return 0.0;
        }

        let exploitability = 8.22 * av_score * ac_score * pr_score * ui_score;
        let base_score = if metrics.scope == Scope::Unchanged {
            (exploitability * impact).min(10.0)
        } else {
            (1.08 * exploitability * impact).min(10.0)
        };

        (base_score * 10.0).ceil() / 10.0
    }

    /// Calculate Temporal Score
    fn calculate_temporal_score(base_score: f64, metrics: &TemporalMetrics) -> f64 {
        let exploit_code_maturity = Self::score_exploit_code_maturity(&metrics.exploit_code_maturity);
        let remediation_level = Self::score_remediation_level(&metrics.remediation_level);
        let report_confidence = Self::score_report_confidence(&metrics.report_confidence);

        let temporal = base_score * exploit_code_maturity * remediation_level * report_confidence;
        (temporal * 10.0).ceil() / 10.0
    }

    /// Calculate Environmental Score
    fn calculate_environmental_score(
        temporal_score: f64,
        metrics: &EnvironmentalMetrics,
    ) -> f64 {
        let conf_req = Self::score_confidentiality_requirement(&metrics.confidentiality_requirement);
        let integ_req = Self::score_integrity_requirement(&metrics.integrity_requirement);
        let avail_req = Self::score_availability_requirement(&metrics.availability_requirement);

        let environmental = temporal_score
            * (1.0 + (conf_req - 1.0) * 0.5 + (integ_req - 1.0) * 0.5 + (avail_req - 1.0) * 0.5);

        (environmental * 10.0).ceil() / 10.0
    }

    /// Score individual metrics
    fn score_attack_vector(av: &AttackVector) -> f64 {
        match av {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }

    fn score_attack_complexity(ac: &AttackComplexity) -> f64 {
        match ac {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }

    fn score_privileges_required(pr: &PrivilegesRequired, scope: &Scope) -> f64 {
        match (pr, scope) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
            (PrivilegesRequired::Low, Scope::Changed) => 0.68,
            (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
            (PrivilegesRequired::High, Scope::Changed) => 0.5,
        }
    }

    fn score_user_interaction(ui: &UserInteraction) -> f64 {
        match ui {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }

    fn score_confidentiality(c: &Confidentiality) -> f64 {
        match c {
            Confidentiality::None => 0.0,
            Confidentiality::Low => 0.22,
            Confidentiality::High => 0.56,
        }
    }

    fn score_integrity(i: &Integrity) -> f64 {
        match i {
            Integrity::None => 0.0,
            Integrity::Low => 0.22,
            Integrity::High => 0.56,
        }
    }

    fn score_availability(a: &Availability) -> f64 {
        match a {
            Availability::None => 0.0,
            Availability::Low => 0.22,
            Availability::High => 0.56,
        }
    }

    fn score_exploit_code_maturity(ecm: &ExploitCodeMaturity) -> f64 {
        match ecm {
            ExploitCodeMaturity::NotDefined => 1.0,
            ExploitCodeMaturity::Unproven => 0.91,
            ExploitCodeMaturity::Proof => 0.94,
            ExploitCodeMaturity::Functional => 0.97,
            ExploitCodeMaturity::HighlyFunctional => 1.0,
        }
    }

    fn score_remediation_level(rl: &RemediationLevel) -> f64 {
        match rl {
            RemediationLevel::NotDefined => 1.0,
            RemediationLevel::Unavailable => 1.0,
            RemediationLevel::Workaround => 0.97,
            RemediationLevel::TemporaryFix => 0.96,
            RemediationLevel::OfficialFix => 0.95,
        }
    }

    fn score_report_confidence(rc: &ReportConfidence) -> f64 {
        match rc {
            ReportConfidence::NotDefined => 1.0,
            ReportConfidence::Unknown => 0.92,
            ReportConfidence::Reasonable => 0.96,
            ReportConfidence::Confirmed => 1.0,
        }
    }

    fn score_confidentiality_requirement(cr: &ConfidentialityRequirement) -> f64 {
        match cr {
            ConfidentialityRequirement::NotDefined => 1.0,
            ConfidentialityRequirement::Low => 0.5,
            ConfidentialityRequirement::Medium => 1.0,
            ConfidentialityRequirement::High => 1.5,
        }
    }

    fn score_integrity_requirement(ir: &IntegrityRequirement) -> f64 {
        match ir {
            IntegrityRequirement::NotDefined => 1.0,
            IntegrityRequirement::Low => 0.5,
            IntegrityRequirement::Medium => 1.0,
            IntegrityRequirement::High => 1.5,
        }
    }

    fn score_availability_requirement(ar: &AvailabilityRequirement) -> f64 {
        match ar {
            AvailabilityRequirement::NotDefined => 1.0,
            AvailabilityRequirement::Low => 0.5,
            AvailabilityRequirement::Medium => 1.0,
            AvailabilityRequirement::High => 1.5,
        }
    }

    /// Calculate confidence score (0.0-1.0)
    fn calculate_confidence(_base: &BaseMetrics, temporal: &TemporalMetrics) -> f64 {
        match temporal.report_confidence {
            ReportConfidence::Confirmed => 0.95,
            ReportConfidence::Reasonable => 0.80,
            ReportConfidence::Unknown => 0.50,
            ReportConfidence::NotDefined => 0.70,
        }
    }

    /// Calculate exploitability score (0.0-1.0)
    fn calculate_exploitability(base: &BaseMetrics) -> f64 {
        let av = Self::score_attack_vector(&base.attack_vector);
        let ac = Self::score_attack_complexity(&base.attack_complexity);
        let pr = Self::score_privileges_required(&base.privileges_required, &base.scope);

        ((av + ac + pr) / 3.0).min(1.0)
    }

    /// Calculate impact score (0.0-1.0)
    fn calculate_impact(base: &BaseMetrics) -> f64 {
        let c = Self::score_confidentiality(&base.confidentiality);
        let i = Self::score_integrity(&base.integrity);
        let a = Self::score_availability(&base.availability);

        ((c + i + a) / 3.0).min(1.0)
    }

    /// Calculate overall score combining all factors
    fn calculate_overall_score(cvss: f64, confidence: f64, exploitability: f64) -> f64 {
        let weighted = (cvss * 0.6) + (confidence * 100.0 * 0.25) + (exploitability * 100.0 * 0.15);
        (weighted / 100.0).min(10.0)
    }

    /// Convert score to severity level (now in correct order)
    fn score_to_severity(score: f64) -> SeverityLevel {
        match score {
            s if s >= 9.0 => SeverityLevel::Critical,
            s if s >= 7.0 => SeverityLevel::High,
            s if s >= 4.0 => SeverityLevel::Medium,
            s if s > 0.0 => SeverityLevel::Low,
            _ => SeverityLevel::None,
        }
    }

    /// Build CVSS vector string
    fn build_cvss_vector(base: &BaseMetrics) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            Self::av_to_string(&base.attack_vector),
            Self::ac_to_string(&base.attack_complexity),
            Self::pr_to_string(&base.privileges_required),
            Self::ui_to_string(&base.user_interaction),
            Self::scope_to_string(&base.scope),
            Self::c_to_string(&base.confidentiality),
            Self::i_to_string(&base.integrity),
            Self::a_to_string(&base.availability),
        )
    }

    fn av_to_string(av: &AttackVector) -> &str {
        match av {
            AttackVector::Network => "N",
            AttackVector::Adjacent => "A",
            AttackVector::Local => "L",
            AttackVector::Physical => "P",
        }
    }

    fn ac_to_string(ac: &AttackComplexity) -> &str {
        match ac {
            AttackComplexity::Low => "L",
            AttackComplexity::High => "H",
        }
    }

    fn pr_to_string(pr: &PrivilegesRequired) -> &str {
        match pr {
            PrivilegesRequired::None => "N",
            PrivilegesRequired::Low => "L",
            PrivilegesRequired::High => "H",
        }
    }

    fn ui_to_string(ui: &UserInteraction) -> &str {
        match ui {
            UserInteraction::None => "N",
            UserInteraction::Required => "R",
        }
    }

    fn scope_to_string(s: &Scope) -> &str {
        match s {
            Scope::Unchanged => "U",
            Scope::Changed => "C",
        }
    }

    fn c_to_string(c: &Confidentiality) -> &str {
        match c {
            Confidentiality::None => "N",
            Confidentiality::Low => "L",
            Confidentiality::High => "H",
        }
    }

    fn i_to_string(i: &Integrity) -> &str {
        match i {
            Integrity::None => "N",
            Integrity::Low => "L",
            Integrity::High => "H",
        }
    }

    fn a_to_string(a: &Availability) -> &str {
        match a {
            Availability::None => "N",
            Availability::Low => "L",
            Availability::High => "H",
        }
    }

    /// Generate security recommendation
    fn generate_recommendation(severity: &SeverityLevel, vuln_type: &str) -> String {
        match severity {
            SeverityLevel::Critical => format!(
                "URGENT: Immediate remediation required for {}. This vulnerability poses critical risk.",
                vuln_type
            ),
            SeverityLevel::High => format!(
                "HIGH PRIORITY: {} vulnerability detected. Address within 2 weeks.",
                vuln_type
            ),
            SeverityLevel::Medium => format!(
                "MEDIUM PRIORITY: {} detected. Schedule remediation within 30 days.",
                vuln_type
            ),
            SeverityLevel::Low => format!(
                "LOW PRIORITY: {} found. Include in next maintenance cycle.",
                vuln_type
            ),
            SeverityLevel::None => "No actionable vulnerability detected.".to_string(),
        }
    }

    /// Build detailed score factors
    fn build_score_factors(
        factors: &mut Vec<ScoreFactor>,
        base: &BaseMetrics,
        _temporal: &TemporalMetrics,
    ) {
        factors.push(ScoreFactor {
            name: "Attack Vector".to_string(),
            value: Self::score_attack_vector(&base.attack_vector),
            weight: 0.15,
            description: format!("Network accessibility: {:?}", base.attack_vector),
        });

        factors.push(ScoreFactor {
            name: "Attack Complexity".to_string(),
            value: Self::score_attack_complexity(&base.attack_complexity),
            weight: 0.10,
            description: format!("Special conditions required: {:?}", base.attack_complexity),
        });

        factors.push(ScoreFactor {
            name: "Confidentiality Impact".to_string(),
            value: Self::score_confidentiality(&base.confidentiality),
            weight: 0.20,
            description: format!("Data exposure risk: {:?}", base.confidentiality),
        });

        factors.push(ScoreFactor {
            name: "Integrity Impact".to_string(),
            value: Self::score_integrity(&base.integrity),
            weight: 0.20,
            description: format!("Data modification risk: {:?}", base.integrity),
        });

        factors.push(ScoreFactor {
            name: "Availability Impact".to_string(),
            value: Self::score_availability(&base.availability),
            weight: 0.20,
            description: format!("Service disruption risk: {:?}", base.availability),
        });

        factors.push(ScoreFactor {
            name: "Scope".to_string(),
            value: if base.scope == Scope::Changed { 0.95 } else { 0.85 },
            weight: 0.15,
            description: format!("Impact boundary: {:?}", base.scope),
        });
    }
}

// CVSS v3.1 Metric Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidentiality {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy)]
pub enum ExploitCodeMaturity {
    NotDefined,
    Unproven,
    Proof,
    Functional,
    HighlyFunctional,
}

#[derive(Debug, Clone, Copy)]
pub enum RemediationLevel {
    NotDefined,
    Unavailable,
    Workaround,
    TemporaryFix,
    OfficialFix,
}

#[derive(Debug, Clone, Copy)]
pub enum ReportConfidence {
    NotDefined,
    Unknown,
    Reasonable,
    Confirmed,
}

#[derive(Debug, Clone, Copy)]
pub enum ConfidentialityRequirement {
    NotDefined,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub enum IntegrityRequirement {
    NotDefined,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy)]
pub enum AvailabilityRequirement {
    NotDefined,
    Low,
    Medium,
    High,
}

#[derive(Debug)]
pub struct BaseMetrics {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: Confidentiality,
    pub integrity: Integrity,
    pub availability: Availability,
}

#[derive(Debug)]
pub struct TemporalMetrics {
    pub exploit_code_maturity: ExploitCodeMaturity,
    pub remediation_level: RemediationLevel,
    pub report_confidence: ReportConfidence,
}

#[derive(Debug)]
pub struct EnvironmentalMetrics {
    pub confidentiality_requirement: ConfidentialityRequirement,
    pub integrity_requirement: IntegrityRequirement,
    pub availability_requirement: AvailabilityRequirement,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_level_ordering() {
        assert!(SeverityLevel::Critical > SeverityLevel::High);
        assert!(SeverityLevel::High > SeverityLevel::Medium);
        assert!(SeverityLevel::Medium > SeverityLevel::Low);
    }

    #[test]
    fn test_score_to_severity() {
        assert_eq!(VulnerabilityScorer::score_to_severity(9.5), SeverityLevel::Critical);
        assert_eq!(VulnerabilityScorer::score_to_severity(7.5), SeverityLevel::High);
        assert_eq!(VulnerabilityScorer::score_to_severity(5.0), SeverityLevel::Medium);
        assert_eq!(VulnerabilityScorer::score_to_severity(2.0), SeverityLevel::Low);
        assert_eq!(VulnerabilityScorer::score_to_severity(0.0), SeverityLevel::None);
    }

    #[test]
    fn test_attack_vector_scoring() {
        assert_eq!(VulnerabilityScorer::score_attack_vector(&AttackVector::Network), 0.85);
        assert_eq!(
            VulnerabilityScorer::score_attack_vector(&AttackVector::Adjacent),
            0.62
        );
        assert_eq!(VulnerabilityScorer::score_attack_vector(&AttackVector::Local), 0.55);
        assert_eq!(VulnerabilityScorer::score_attack_vector(&AttackVector::Physical), 0.2);
    }

    #[test]
    fn test_cvss_vector_generation() {
        let base = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: Confidentiality::High,
            integrity: Integrity::High,
            availability: Availability::High,
        };

        let vector = VulnerabilityScorer::build_cvss_vector(&base);
        assert!(vector.starts_with("CVSS:3.1/"));
        assert!(vector.contains("AV:N"));
        assert!(vector.contains("AC:L"));
    }

    #[test]
    fn test_cvss_scoring() {
        let base = BaseMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality: Confidentiality::High,
            integrity: Integrity::High,
            availability: Availability::High,
        };

        let score = VulnerabilityScorer::calculate_cvss_base(&base);
        assert!(score > 0.0);
        assert!(score <= 10.0);
    }

    #[test]
    fn test_recommendation_generation() {
        let critical_rec = VulnerabilityScorer::generate_recommendation(&SeverityLevel::Critical, "SQL Injection");
        assert!(critical_rec.to_lowercase().contains("urgent"));

        let high_rec = VulnerabilityScorer::generate_recommendation(&SeverityLevel::High, "XSS");
        assert!(high_rec.to_lowercase().contains("high priority"));
    }
}
