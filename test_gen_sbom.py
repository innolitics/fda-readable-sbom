from gen_sbom import merge_sboms


def test_merge_sboms_packages():
    sbom1 = {
        "creationInfo": {"created": "2022-08-03T19:42:37Z"},
        "packages": [
            {"SPDXID": "1", "name": "a", "versionInfo": "1.0.0"},
            {"SPDXID": "2", "name": "b", "versionInfo": "1.0.0"},
            {"SPDXID": "4", "name": "b", "versionInfo": "1.3.0"},
            {"SPDXID": "3", "name": "c", "versionInfo": "1.0.0"},
            {"SPDXID": "5", "name": "d", "versionInfo": "1.0.0"},
        ],
    }
    sbom2 = {
        "creationInfo": {"created": "2023-08-03T19:42:37Z"},
        "packages": [
            {"SPDXID": "11", "name": "a", "versionInfo": "2.0.0"},
            {"SPDXID": "22", "name": "b", "versionInfo": "0.9.0"},
            {"SPDXID": "33", "name": "c", "versionInfo": "2.0.0"},
            {"SPDXID": "44", "name": "e", "versionInfo": "1.0.0"},
        ],
    }
    expected_sbom = {
        "creationInfo": {"created": "2023-08-03T19:42:37Z"},
        "packages": [
            {"SPDXID": "11", "name": "a", "versionInfo": "2.0.0"},
            {"SPDXID": "4", "name": "b", "versionInfo": "1.3.0"},
            {"SPDXID": "33", "name": "c", "versionInfo": "2.0.0"},
            {"SPDXID": "5", "name": "d", "versionInfo": "1.0.0"},
            {"SPDXID": "44", "name": "e", "versionInfo": "1.0.0"},
        ],
    }
    assert merge_sboms(sbom1, sbom2) == expected_sbom
