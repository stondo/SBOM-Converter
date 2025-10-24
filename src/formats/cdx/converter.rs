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
}
