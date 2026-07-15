from vulnerabilities import load_enabled_vulnerabilities


def test_load_enabled_vulnerabilities_filters_disabled_rows(tmp_path):
    csv_file = tmp_path / "vulnerabilities.csv"
    csv_file.write_text(
        "enabled,type,risk_factor\n"
        "True,PIILeakage,Privacy\n"
        "False,Bias,Ethics\n"
        "0,Toxicity,Safety\n"
        ",Misinformation,Trust\n",
        encoding="utf-8",
    )

    rows = load_enabled_vulnerabilities(csv_file)

    assert [row["type"] for row in rows] == ["PIILeakage"]


def test_load_enabled_vulnerabilities_defaults_missing_enabled_column_to_enabled(tmp_path):
    csv_file = tmp_path / "vulnerabilities.csv"
    csv_file.write_text(
        "type,risk_factor\n"
        "PIILeakage,Privacy\n"
        "Misinformation,Trust\n",
        encoding="utf-8",
    )

    rows = load_enabled_vulnerabilities(csv_file)

    assert [row["type"] for row in rows] == ["PIILeakage", "Misinformation"]
