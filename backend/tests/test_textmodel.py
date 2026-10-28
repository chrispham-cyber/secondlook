import gzip
import json

import pytest

from app.scoring import CAP_WHEN_SURE_SAFE, combine
from app.signals.textmodel import TextModel, features, load_default
from tests.fakes import FakeAnalyzer, analysis
from tests.test_api import make_client
from tests.test_scoring import link


def test_features_ignore_exact_digits_and_flag_phones():
    a, b = features("Call 0906-123-4567 now"), features("Call 0871-999-0000 now")
    assert a == b
    assert "f:phone" in a and "w:call" in a and "w:0000" in a


def test_exported_model_matches_scikit_learn(tmp_path):
    sklearn = pytest.importorskip("sklearn")  # noqa: F841 - training-only dependency
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    texts = ["You won a prize, call now", "see you at lunch", "verify your account at bit.ly/x", "dinner at 7?"] * 3
    y = [1, 0, 1, 0] * 3
    vec = TfidfVectorizer(analyzer=features, sublinear_tf=True, lowercase=False)
    clf = LogisticRegression().fit(vec.fit_transform(texts), y)
    names = vec.get_feature_names_out()
    data = {
        "intercept": float(clf.intercept_[0]),
        "features": {f: [i, c] for f, i, c in zip(names, vec.idf_, clf.coef_[0], strict=True)},
    }
    path = tmp_path / "m.json.gz"
    path.write_bytes(gzip.compress(json.dumps(data).encode()))
    model = TextModel.load(path)
    for t in ["call now to claim your prize", "lunch tomorrow?", "totally unseen words"]:
        assert model.probability(t) == pytest.approx(clf.predict_proba(vec.transform([t]))[0, 1], abs=1e-9)


def test_bundled_model_separates_obvious_cases():
    model = load_default()
    assert model is not None
    assert model.score("URGENT! You have won a £1000 prize. Call 09061701461 to claim now") > 80
    assert model.score("ok see you at 6, I'll bring the salad") < 20


def test_text_model_caps_ai_but_never_rule_floors():
    assert combine(90, [], [], text_model=5)[0] == CAP_WHEN_SURE_SAFE
    assert combine(90, [], [], text_model=50)[0] == 90
    assert combine(40, [], [], text_model=5)[0] == 40  # only ever lowers a high AI score to "be careful"
    assert combine(90, [link(("lookalike_domain", "high"))], [], text_model=1)[0] == 85
    assert combine(None, [], [], text_model=80)[0] == 80  # without the AI, it raises the rules score


def test_capped_scan_says_be_careful(tmp_path):
    jumpy = FakeAnalyzer(analysis(scam_probability=85, headline="This is a scam."))
    with make_client(tmp_path, jumpy) as c:
        body = c.post("/api/scan", data={"text": "ok see you at 6, I'll bring the salad"}).json()
    assert body["verdict"] == "suspicious" and body["risk_score"] == CAP_WHEN_SURE_SAFE
    assert body["headline"] != "This is a scam."
    assert body["score_breakdown"]["text_model_score"] < 10
