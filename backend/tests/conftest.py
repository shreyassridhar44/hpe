# -*- coding: utf-8 -*-
"""
conftest.py — Shared pytest fixtures and infrastructure mocks.
Mocks all external infrastructure modules so tests can run without
Kafka, Elasticsearch, Vault, or PostgreSQL installed.
"""
import sys
from unittest.mock import MagicMock

# Mock all infrastructure client libraries before any app imports
_infra_mocks = [
    'confluent_kafka', 'confluent_kafka.admin',
    'elasticsearch',
    'hvac',
    'psycopg2', 'psycopg2.pool', 'psycopg2.extras',
]

for mod in _infra_mocks:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

import pytest
from app.config import MODEL_PATH
from app import inference

_cached_artifacts = None

@pytest.fixture(scope="session", autouse=True)
def load_ml_model_once():
    global _cached_artifacts
    try:
        inference.load_model(MODEL_PATH)
        if inference._is_loaded:
            _cached_artifacts = {
                "xgb_model": inference._xgb_model,
                "lgbm_model": inference._lgbm_model,
                "rf_model": inference._rf_model,
                "gb_model": inference._gb_model,
                "label_encoders": inference._label_encoders,
                "feature_cols": inference._feature_cols,
                "weights": inference._weights,
                "best_threshold": inference._best_threshold,
                "user_profiles": inference._user_profiles,
            }
    except Exception as e:
        print(f"Warning: Failed to load ML model in tests: {e}")
    
    # Mock DB pool initialization so tests don't log pool failure
    try:
        from app import db
        db._pool = MagicMock()
    except Exception:
        pass

@pytest.fixture(scope="function", autouse=True)
def restore_ml_model_state(request):
    # If the test is in test_inference, let it manipulate state freely.
    # Otherwise, ensure the real ML model state is restored and active.
    if "test_inference" not in request.node.nodeid:
        if _cached_artifacts is not None:
            inference._xgb_model = _cached_artifacts["xgb_model"]
            inference._lgbm_model = _cached_artifacts["lgbm_model"]
            inference._rf_model = _cached_artifacts["rf_model"]
            inference._gb_model = _cached_artifacts["gb_model"]
            inference._label_encoders = _cached_artifacts["label_encoders"]
            inference._feature_cols = _cached_artifacts["feature_cols"]
            inference._weights = _cached_artifacts["weights"]
            inference._best_threshold = _cached_artifacts["best_threshold"]
            inference._user_profiles = _cached_artifacts["user_profiles"]
            inference._is_loaded = True



