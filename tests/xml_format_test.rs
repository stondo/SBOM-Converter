use sbom_converter::formats::cdx::{CdxDocument, xml};
use std::io::Cursor;

#[test]
fn test_parse_minimal_cdx_xml() {
    // Create minimal CDX XML inline
    let xml_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata>
    <timestamp>2024-01-01T00:00:00Z</timestamp>
  </metadata>
</bom>"#;

    let reader = Cursor::new(xml_content.as_bytes());
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
