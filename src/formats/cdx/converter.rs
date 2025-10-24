//! Conversion between CdxDocument (XML-friendly) and JSON format

use super::document::*;
use serde_json::{json, Value};

/// Convert CdxDocument to JSON Value for JSON serialization
pub fn document_to_json(doc: &CdxDocument) -> Value {
    let mut bom = json!({});
    
    // Top-level attributes
    if let Some(xmlns) = &doc.xmlns {
        // Skip xmlns in JSON
        let _ = xmlns;
    }
    
    bom["bomFormat"] = json!("CycloneDX");
    bom["specVersion"] = json!(doc.spec_version.clone().unwrap_or_else(|| "1.6".to_string()));
    bom["version"] = json!(doc.version);
    
    if let Some(serial) = &doc.serial_number {
        bom["serialNumber"] = json!(serial);
    }
    
    // Metadata
    if let Some(metadata) = &doc.metadata {
        let mut meta = json!({});
        
        if let Some(timestamp) = &metadata.timestamp {
            meta["timestamp"] = json!(timestamp);
        }
        
        if let Some(tools) = &metadata.tools {
            meta["tools"] = json!(tools.tools.iter().map(|t| {
                let mut tool = json!({});
                if let Some(vendor) = &t.vendor {
                    tool["vendor"] = json!(vendor);
                }
                if let Some(name) = &t.name {
                    tool["name"] = json!(name);
                }
                if let Some(version) = &t.version {
                    tool["version"] = json!(version);
                }
                tool
            }).collect::<Vec<_>>());
        }
        
        bom["metadata"] = meta;
    }
    
    // Components - flatten the wrapper
    if let Some(components) = &doc.components {
        let comps = components.components.iter().map(|c| {
            let mut comp = json!({
                "type": c.component_type,
                "name": c.name,
            });
            
            if let Some(bom_ref) = &c.bom_ref {
                comp["bom-ref"] = json!(bom_ref);
            }
            if let Some(version) = &c.version {
                comp["version"] = json!(version);
            }
            if let Some(description) = &c.description {
                comp["description"] = json!(description);
            }
            if let Some(purl) = &c.purl {
                comp["purl"] = json!(purl);
            }
            
            comp
        }).collect::<Vec<_>>();
        
        bom["components"] = json!(comps);
    }
    
    bom
}

/// Convert JSON Value (standard CDX JSON) to CdxDocument for XML serialization
pub fn json_to_document(value: &Value) -> Result<CdxDocument, String> {
    let mut doc = CdxDocument {
        xmlns: Some("http://cyclonedx.org/schema/bom/1.6".to_string()),
        version: value.get("version").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
        ..Default::default()
    };
    
    // Top-level fields
    if let Some(spec_version) = value.get("specVersion").and_then(|v| v.as_str()) {
        doc.spec_version = Some(spec_version.to_string());
    }
    
    if let Some(serial) = value.get("serialNumber").and_then(|v| v.as_str()) {
        doc.serial_number = Some(serial.to_string());
    }
    
    if let Some(bom_format) = value.get("bomFormat").and_then(|v| v.as_str()) {
        doc.bom_format = Some(bom_format.to_string());
    }
    
    // Metadata
    if let Some(metadata) = value.get("metadata") {
        let mut meta = CdxMetadata {
            timestamp: metadata.get("timestamp").and_then(|v| v.as_str()).map(|s| s.to_string()),
            tools: None,
            component: None,
        };
        
        // Tools
        if let Some(tools_array) = metadata.get("tools").and_then(|v| v.as_array()) {
            let tools: Vec<CdxTool> = tools_array.iter().filter_map(|t| {
                Some(CdxTool {
                    vendor: t.get("vendor").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    name: t.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    version: t.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                })
            }).collect();
            
            if !tools.is_empty() {
                meta.tools = Some(CdxTools { tools });
            }
        }
        
        doc.metadata = Some(meta);
    }
    
    // Components
    if let Some(components_array) = value.get("components").and_then(|v| v.as_array()) {
        let components: Vec<CdxComponent> = components_array.iter().filter_map(|c| {
            let component_type = c.get("type").and_then(|v| v.as_str())?.to_string();
            let name = c.get("name").and_then(|v| v.as_str())?.to_string();
            
            Some(CdxComponent {
                component_type,
                bom_ref: c.get("bom-ref").and_then(|v| v.as_str()).map(|s| s.to_string()),
                name,
                version: c.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                description: c.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                purl: c.get("purl").and_then(|v| v.as_str()).map(|s| s.to_string()),
                hashes: None, // TODO: Handle hashes if needed
                licenses: None, // TODO: Handle licenses if needed
            })
        }).collect();
        
        if !components.is_empty() {
            doc.components = Some(CdxComponents { components });
        }
    }
    
    // Dependencies
    if let Some(deps_array) = value.get("dependencies").and_then(|v| v.as_array()) {
        let dependencies: Vec<CdxDependency> = deps_array.iter().filter_map(|d| {
            let dep_ref = d.get("ref").and_then(|v| v.as_str())?.to_string();
            
            let depends_on = d.get("dependsOn")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| r.as_str().map(|s| CdxDependsOn {
                            dependency_ref: s.to_string(),
                        }))
                        .collect()
                })
                .unwrap_or_default();
            
            Some(CdxDependency {
                dependency_ref: dep_ref,
                depends_on,
            })
        }).collect();
        
        if !dependencies.is_empty() {
            doc.dependencies = Some(CdxDependencies { dependencies });
        }
    }
    
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_document_to_json() {
        let doc = CdxDocument {
            version: 1,
            spec_version: Some("1.6".to_string()),
            ..Default::default()
        };
        
        let json = document_to_json(&doc);
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.6");
        assert_eq!(json["version"], 1);
    }
    
    #[test]
    fn test_json_to_document() {
        let json = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "serialNumber": "urn:uuid:test-123",
            "components": [
                {
                    "type": "library",
                    "name": "example",
                    "version": "1.0.0",
                    "bom-ref": "pkg:npm/example@1.0.0"
                }
            ]
        });
        
        let doc = json_to_document(&json).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.spec_version, Some("1.6".to_string()));
        assert_eq!(doc.serial_number, Some("urn:uuid:test-123".to_string()));
        assert!(doc.components.is_some());
        
        let components = doc.components.unwrap();
        assert_eq!(components.components.len(), 1);
        assert_eq!(components.components[0].name, "example");
    }
}
