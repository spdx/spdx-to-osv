# spdx-to-osv
Produce an Open Source Vulnerability JSON file based on information in an SPDX document

## Usage
`java -jar spdx-to-osv-with-dependencies.jar -I SpdxFile.spdx -O OSVOutput.json`

where SpdxFile.spdx is an SPDX file in one of the following file extensions:
- .json JSON SPDX format
- .yaml YAML SPDX format
- .spdx Tag/Value SPDX format
- .rdf.xml, .rdf - RDF/XML SPDX format
- .xlsx, .xls Spreadsheet SPDX format

Optional parameters:
- `-a`,`--all` Include vulnerabilities for all packages in the SPDX file. Default is to only include vulnerabilities related to the element described by the document.
-  `-f`,`--inputFormat <arg>`   Input file format - RDFXML, JSON, XLS, XLSX, YAML, or TAG

The utility produces an output file OSVOutput.json in the [OSV JSON format](https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit)

## How it Works
The utility uses the [OSV API's](https://osv.dev/) to query the OSV database using the following information if available:
- Package name and version
- CVE ExternalRef
- Github download location if it includes a hash or version tag

Only vulnerabilities related to the SPDX element described by the document will be reported unless the `--all` option is used in which case vulnerabilities for all packages in the document will be provided.
