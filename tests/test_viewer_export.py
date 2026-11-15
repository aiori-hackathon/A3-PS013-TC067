from pathlib import Path
import tempfile
from forensic.ingest import ingest
from forensic.build import build
from forensic.skew import skew
from forensic.report import generate_report


def test_viewer_export_report(tmp_path):
    case_dir = tmp_path / "s3_clock_skew"
    sources_json = Path("scenarios/s3_clock_skew/sources.json")
    assert sources_json.exists()

    ingest(case_dir, sources_json, collector="test")
    build(case_dir)
    skew(case_dir)

    with tempfile.TemporaryDirectory() as report_tmp:
        tmp = Path(report_tmp)
        out_html = tmp / "r.html"
        out_json = tmp / "r.json"
        out_csv = tmp / "r.csv"

        generate_report(case_dir, out_html, out_json, out_csv)

        assert out_html.exists()
        assert out_json.exists()
        assert out_csv.exists()

        html_content = out_html.read_text(encoding="utf-8")
        assert "Report for s3_clock_skew" in html_content
        assert "Evidence Manifest" in html_content
