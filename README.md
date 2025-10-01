# fda-readable-sbom
A python script that translates machine-readable SBOMs into a format suitable for FDA submissions.

# gen_sbom.py

This script merges SBOMs generated from Github's Dependabot tool
and outputs it as a human readable excel file.

Supported SBOM formats:
- SPDX JSON v2.3
- CycloneDX JSON v1.6

# Usage
If [uv](https://docs.astral.sh/uv/) is installed, you can run the tool without setting up an environment. Simply execute the script with the required arguments.


```
usage: gen_sbom.py [-h] client_name input_directory output_file

positional arguments:
  input_directory  Github SBOM json files directory.
  output_file      Output combined SBOM excel file path.

optional arguments:
  -h, --help       show this help message and exit
```
