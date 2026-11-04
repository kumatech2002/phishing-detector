"""
test_api.py — Integration tests for Flask API endpoints.
"""

import sys
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─── Health endpoint ─────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        res = client.get('/api/health')
        assert res.status_code == 200

    def test_health_response_structure(self, client):
        data = client.get('/api/health').get_json()
        assert data['ok'] is True
        assert 'status' in data
        assert 'model_loaded' in data

    def test_health_status_ok(self, client):
        data = client.get('/api/health').get_json()
        assert data['status'] == 'ok'


# ─── Analyze endpoint ─────────────────────────────────────────

class TestAnalyzeEndpoint:
    def test_missing_body_returns_400(self, client):
        res = client.post('/api/analyze', content_type='application/json')
        assert res.status_code == 400

    def test_missing_domain_field(self, client):
        res = client.post('/api/analyze',
                          data=json.dumps({}),
                          content_type='application/json')
        data = res.get_json()
        assert data['ok'] is False

    def test_empty_domain(self, client):
        res = client.post('/api/analyze',
                          data=json.dumps({'domain': ''}),
                          content_type='application/json')
        assert res.status_code == 422
        data = res.get_json()
        assert data['ok'] is False

    def test_invalid_domain(self, client):
        res = client.post('/api/analyze',
                          data=json.dumps({'domain': 'not_a_domain'}),
                          content_type='application/json')
        assert res.status_code == 422

    def test_sql_injection_attempt(self, client):
        # Should be caught by validation, not crash the server
        res = client.post('/api/analyze',
                          data=json.dumps({'domain': "'; DROP TABLE scan_history; --"}),
                          content_type='application/json')
        # Either rejected as invalid domain or handled safely
        assert res.status_code in (400, 422, 503)

    def test_very_long_domain(self, client):
        res = client.post('/api/analyze',
                          data=json.dumps({'domain': 'a' * 300 + '.com'}),
                          content_type='application/json')
        assert res.status_code == 422

    def test_valid_domain_with_model(self, client, mock_model_artifacts):
        res = client.post('/api/analyze',
                          data=json.dumps({'domain': 'gtbank-secure.xyz'}),
                          content_type='application/json')
        assert res.status_code == 200
        data = res.get_json()
        assert data['ok'] is True
        assert 'result' in data
        result = data['result']
        assert 'label' in result
        assert 'confidence' in result
        assert 'features' in result
        assert 'risk_indicators' in result
        assert 'disclaimer' in result

    def test_analyze_domain_with_scheme_stripped(self, client, mock_model_artifacts):
        res = client.post('/api/analyze',
                          data=json.dumps({'domain': 'https://gtbank.com'}),
                          content_type='application/json')
        assert res.status_code == 200


# ─── History endpoint ─────────────────────────────────────────

class TestHistoryEndpoint:
    def test_get_history_returns_200(self, client):
        res = client.get('/api/history')
        assert res.status_code == 200

    def test_history_response_structure(self, client):
        data = client.get('/api/history').get_json()
        assert data['ok'] is True
        assert 'items' in data
        assert 'total' in data
        assert 'page' in data
        assert 'pages' in data

    def test_history_pagination_params(self, client):
        res = client.get('/api/history?page=1&per_page=5')
        assert res.status_code == 200

    def test_history_invalid_page(self, client):
        res = client.get('/api/history?page=abc')
        assert res.status_code == 400

    def test_delete_nonexistent_scan(self, client):
        res = client.delete('/api/history/999999')
        assert res.status_code == 404

    def test_get_nonexistent_scan(self, client):
        res = client.get('/api/history/999999')
        assert res.status_code == 404


# ─── Stats endpoint ───────────────────────────────────────────

class TestStatsEndpoint:
    def test_stats_returns_200(self, client):
        res = client.get('/api/stats')
        assert res.status_code == 200

    def test_stats_response_structure(self, client):
        data = client.get('/api/stats').get_json()
        assert data['ok'] is True
        assert 'stats' in data
        stats = data['stats']
        assert 'total_scans' in stats
        assert 'phishing_count' in stats
        assert 'legitimate_count' in stats
        assert 'detection_rate' in stats

    def test_stats_non_negative(self, client):
        stats = client.get('/api/stats').get_json()['stats']
        assert stats['total_scans'] >= 0
        assert stats['phishing_count'] >= 0
        assert stats['legitimate_count'] >= 0
        assert 0.0 <= stats['detection_rate'] <= 1.0


# ─── Model info endpoint ──────────────────────────────────────

class TestModelInfoEndpoint:
    def test_model_info_with_loaded_model(self, client, mock_model_artifacts):
        res = client.get('/api/model-info')
        assert res.status_code == 200
        data = res.get_json()
        assert data['ok'] is True
        assert 'model' in data
        model = data['model']
        assert 'best_model' in model
        assert 'winner_metrics' in model

    def test_model_info_without_model(self, client):
        """Should return 503 when model files are missing."""
        import backend.ml.predict as pred_mod
        original_model = pred_mod._model
        original_meta  = pred_mod._meta
        pred_mod._model = None
        pred_mod._meta  = None

        # Patch the config imported inside _load_artifacts
        from unittest.mock import MagicMock
        from pathlib import Path
        mock_config = MagicMock()
        mock_config.MODEL_PATH = Path("/nonexistent/model.joblib")
        mock_config.META_PATH  = Path("/nonexistent/meta.json")

        with patch("backend.config.config", mock_config):
            res = client.get("/api/model-info")

        pred_mod._model = original_model
        pred_mod._meta  = original_meta
        assert res.status_code in (503, 500)


# ─── Error handling ───────────────────────────────────────────

class TestErrorHandling:
    def test_404_returns_json(self, client):
        res = client.get('/api/nonexistent-endpoint')
        assert res.status_code == 404
        data = res.get_json()
        assert 'error' in data

    def test_method_not_allowed(self, client):
        # Flask's catch-all SPA route handles all GET paths, so unregistered
        # method + path combinations return 404 or 405 depending on routing.
        res = client.get('/api/analyze')
        assert res.status_code in (404, 405)
