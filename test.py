import pytest
from solution import DependencyScanner, InvalidManifestError, InvalidVulnerabilityDBError, VersionParseError
def test_basic_detection():
    scanner = DependencyScanner()
    manifest = {"name":"root","version":"0.0.0","dependencies":[{"name":"A","version":"1.2.0","dependencies":[{"name":"B","version":"2.0.0"}]}]}
    vuln_db = [{"id":"V1","package":"A","versions":">=1.0.0,<2.0.0","severity":"high"},{"id":"V2","package":"B","versions":"=2.0.0","severity":"medium"}]
    out = scanner.scan(manifest, vuln_db)
    expected = [
        {"vuln_id":"V1","package":"A","version":"1.2.0","path":["root","A"],"severity":"high"},
        {"vuln_id":"V2","package":"B","version":"2.0.0","path":["root","A","B"],"severity":"medium"}
    ]
    assert out == expected
def test_duplicate_package_versions():
    scanner = DependencyScanner()
    branch1 = {"name":"A","version":"1.2.0","dependencies":[]}
    branch2 = {"name":"A","version":"2.0.0","dependencies":[]}
    manifest = {"name":"root","version":"0.0.0","dependencies":[branch1,{"name":"C","version":"0.1.0","dependencies":[branch2]}]}
    vuln_db = [{"id":"V10","package":"A","versions":"<1.5.0","severity":"critical"}]
    out = scanner.scan(manifest, vuln_db)
    expected = [{"vuln_id":"V10","package":"A","version":"1.2.0","path":["root","A"],"severity":"critical"}]
    assert out == expected
def test_cycle_handling():
    scanner = DependencyScanner()
    d = {"name":"D","version":"1.0.0","dependencies":[]}
    e = {"name":"E","version":"1.0.0","dependencies":[]}
    d["dependencies"].append(e)
    e["dependencies"].append(d)
    manifest = {"name":"root","version":"0.0.0","dependencies":[d]}
    vuln_db = [{"id":"VE","package":"E","versions":"<=1.0.0","severity":"medium"}]
    out = scanner.scan(manifest, vuln_db)
    expected = [{"vuln_id":"VE","package":"E","version":"1.0.0","path":["root","D","E"],"severity":"medium"}]
    assert out == expected
def test_invalid_manifest_type():
    scanner = DependencyScanner()
    with pytest.raises(InvalidManifestError) as e:
        scanner.scan([], [])
    assert str(e.value) == "Invalid manifest: expected dict with 'name' and 'version' keys."
def test_invalid_vuln_db_type():
    scanner = DependencyScanner()
    manifest = {"name":"root","version":"0.0.0"}
    with pytest.raises(InvalidVulnerabilityDBError) as e:
        scanner.scan(manifest, "not a list")
    assert str(e.value) == "Invalid vulnerability database: expected list of entries."
def test_invalid_version_string_in_manifest():
    scanner = DependencyScanner()
    manifest = {"name":"root","version":"0.0.0","dependencies":[{"name":"F","version":"1.2","dependencies":[]}]}
    vuln_db = []
    with pytest.raises(VersionParseError) as e:
        scanner.scan(manifest, vuln_db)
    assert str(e.value) == "Invalid version: 1.2"
def test_caching_effectiveness():
    scanner = DependencyScanner()
    a1 = {"name":"A","version":"1.0.0","dependencies":[]}
    a2 = {"name":"A","version":"1.0.0","dependencies":[]}
    b = {"name":"B","version":"0.0.1","dependencies":[a1,a2,a1]}
    manifest = {"name":"root","version":"0.0.0","dependencies":[b]}
    vuln_db = [{"id":"VC","package":"A","versions":">=0.0.0","severity":"low"}]
    out = scanner.scan(manifest, vuln_db)
    assert len(out) == 2
    assert scanner.compare_count < 50
    