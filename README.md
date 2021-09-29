# spdx-to-osv
Produce an Open Source Vulnerability JSON file based on information in an SPDX document

## Usage
java -jar spdx-to-osv-with-dependencies.jar SpdxFile.spdx OSVOutput.json

where SpdxFile.spdx is an SPDX file in one of the following file extensions:
- .json JSON SPDX format
- .yaml YAML SPDX format
- .spdx Tag/Value SPDX format
- .rdf.xml, .rdf - RDF/XML SPDX format
- .xlsx, .xls Spreadsheet SPDX format

The utility produces an output file OSVOutput.json in the [OSV JSON format](https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit)

## How it Works
The utility uses the [OSV API's](https://osv.dev/) to query the OSV database using the following information if available:
- Package name and version
- CVE ExternalRef
- Github download location if it includes a hash or version tag
