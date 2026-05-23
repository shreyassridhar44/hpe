"""
Tests for the ML pipeline F1 validation parser logic.
Validates that the regex correctly extracts F1 scores from sklearn's
classification_report format — the same format written by export_v2_model.py.
"""
import re
import pytest


SAMPLE_REPORT = """
Confusion Matrix:
[[8842  158]
 [  92  908]]

Classification Report:
              precision    recall  f1-score   support

      Normal       0.99      0.98      0.99      9000
      Threat       0.85      0.91      0.88      1000

    accuracy                           0.97     10000
   macro avg       0.92      0.95      0.93     10000
weighted avg       0.97      0.97      0.97     10000

Best Threshold: 0.4231
Training Duration: 42.3s
"""


def _parse_threat_f1(content: str) -> float | None:
    m = re.search(r'Threat\s+[\d.]+\s+[\d.]+\s+([\d.]+)\s+\d+', content)
    return float(m.group(1)) if m else None


def _parse_threshold(content: str) -> float | None:
    m = re.search(r'Best Threshold:\s*([\d.]+)', content)
    return float(m.group(1)) if m else None


def _parse_macro_f1(content: str) -> float | None:
    m = re.search(r'macro avg\s+[\d.]+\s+[\d.]+\s+([\d.]+)\s+\d+', content)
    return float(m.group(1)) if m else None


class TestClassificationReportParser:
    def test_threat_f1_parsed_correctly(self):
        assert _parse_threat_f1(SAMPLE_REPORT) == pytest.approx(0.88)

    def test_threshold_parsed_correctly(self):
        assert _parse_threshold(SAMPLE_REPORT) == pytest.approx(0.4231)

    def test_macro_f1_parsed_correctly(self):
        assert _parse_macro_f1(SAMPLE_REPORT) == pytest.approx(0.93)

    def test_passes_above_threshold(self):
        f1 = _parse_threat_f1(SAMPLE_REPORT)
        assert f1 >= 0.70

    def test_fails_below_threshold(self):
        low_report = SAMPLE_REPORT.replace("      0.88      1000", "      0.55      1000")
        f1 = _parse_threat_f1(low_report)
        assert f1 < 0.70

    def test_returns_none_on_malformed_report(self):
        assert _parse_threat_f1("this is not a report") is None
        assert _parse_threshold("this is not a report") is None
