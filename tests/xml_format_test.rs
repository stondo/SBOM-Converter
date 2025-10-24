use sbom_converter::formats::cdx::{xml, CdxDocument};
use std::fs::File;
use std::io::BufReader;

#[test]
fn test_parse_minimal_cdx_xml() {
    let xml_path = "test-data/minimal-cdx.xml";
    let file = File::open(xml_path).expect("Failed to open test XML file");
    let reader = BufReader::new(file);
    
    let result = xml::parse(reader);
    
    if let Err(e) = &result {
        println!("Parse error: {:?}", e);
    }
    
    assert!(result.is_ok(), "Should parse minimal CDX XML");
    
    let doc = result.unwrap();
    assert_eq!(doc.version, 1);
}

#[test]
fn test_xml_roundtrip() {
    // Create a minimal document
    let doc = CdxDocument {
        version: 1,
        spec_version: Some("1.6".to_string()),
        xmlns: Some("http://cyclonedx.org/schema/bom/1.6".to_string()),
        ..Default::default()
    };
    
    // Write to XML
    let mut output = Vec::new();
    let write_result = xml::write(&mut output, &doc);
    
    if let Err(e) = &write_result {
        println!("Write error: {:?}", e);
    }
    
    assert!(write_result.is_ok(), "Should write CDX XML");
    
    let xml_str = String::from_utf8(output).unwrap();
    println!("Generated XML:\n{}", xml_str);
    
    assert!(xml_str.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml_str.contains("version=\"1\""));
}
