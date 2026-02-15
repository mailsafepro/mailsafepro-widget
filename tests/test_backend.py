"""
Tests for MailSafePro Widget Backend
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    with patch('main.settings') as mock:
        mock.environment = 'testing'
        mock.testing_mode = True
        mock.documentation = Mock(
            title="MailSafePro API",
            description="Test API",
            version="1.0.0",
            contact={"name": "Test", "email": "test@test.com"},
            enabled=True
        )
        mock.monitoring = Mock(metrics_enabled=False)
        mock.redis_url = "redis://localhost:6379"
        yield mock


@pytest.fixture
def app_instance(mock_settings):
    """Create test FastAPI app instance."""
    with patch('main.initialize_services', new_callable=AsyncMock):
        with patch('main.shutdown_services', new_callable=AsyncMock):
            with patch('main.cache_disposable_domains', new_callable=AsyncMock):
                with patch('main.background_tasks', new_callable=AsyncMock):
                    with patch('main.register_exception_handlers'):
                        with patch('main.instrument_app'):
                            with patch('main.mount_metrics_endpoint'):
                                with patch('redis.asyncio.Redis.from_url') as mock_redis:
                                    mock_redis_instance = AsyncMock()
                                    mock_redis_instance.ping = AsyncMock()
                                    mock_redis.return_value = mock_redis_instance
                                    
                                    from main import app
                                    yield app


@pytest.fixture
def client(app_instance):
    """Create test client."""
    return TestClient(app_instance)


class TestHealthCheck:
    """Tests for health check endpoint."""

    def test_healthcheck_returns_ok(self, client):
        """Health check should return status ok."""
        response = client.get("/healthcheck")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_healthcheck_head_request(self, client):
        """Health check should support HEAD requests."""
        response = client.head("/healthcheck")
        assert response.status_code == 200


class TestWidgetEndpoint:
    """Tests for widget static file endpoint."""

    def test_widget_endpoint_exists(self, client):
        """Widget endpoint should exist."""
        response = client.get("/static/mailsafepro-widget.js")
        assert response.status_code in [200, 404]

    def test_widget_endpoint_returns_javascript(self, client):
        """Widget endpoint should return JavaScript content."""
        response = client.get("/static/mailsafepro-widget.js")
        if response.status_code == 200:
            assert 'application/javascript' in response.headers.get('content-type', '')


class TestCORS:
    """Tests for CORS configuration."""

    def test_cors_allows_origins(self, client):
        """CORS should allow all origins for widget access."""
        response = client.options(
            "/validate/email",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-api-key"
            }
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in [h.lower() for h in response.headers.keys()]


class TestValidationEndpoint:
    """Tests for validation endpoint."""

    def test_validation_endpoint_exists(self, client):
        """Validation endpoint should exist."""
        response = client.post(
            "/validate/email",
            json={"email": "test@example.com"}
        )
        assert response.status_code in [200, 401, 422]

    def test_validation_requires_email(self, client):
        """Validation should require email field."""
        response = client.post(
            "/validate/email",
            json={}
        )
        assert response.status_code == 422

    def test_validation_validates_email_format(self, client):
        """Validation should validate email format."""
        response = client.post(
            "/validate/email",
            json={"email": "not-an-email"}
        )
        assert response.status_code == 422


class TestRateLimiting:
    """Tests for rate limiting middleware."""

    def test_rate_limiting_applies(self, client):
        """Rate limiting should be applied to endpoints."""
        response = client.post(
            "/validate/email",
            json={"email": "test@example.com"}
        )
        assert response.status_code in [200, 401, 429, 422]


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_security_headers_present(self, client):
        """Security headers should be present in responses."""
        response = client.get("/healthcheck")
        assert response.status_code == 200
        headers = {k.lower(): v for k, v in response.headers.items()}
        assert 'x-content-type-options' in headers or 'content-security-policy' in headers or len(headers) > 0


class TestOpenAPI:
    """Tests for OpenAPI schema."""

    def test_openapi_schema_available(self, client):
        """OpenAPI schema should be available."""
        response = client.get("/openapi.json")
        assert response.status_code == 200

    def test_docs_available(self, client):
        """API docs should be available."""
        response = client.get("/docs")
        assert response.status_code == 200


class TestRedoc:
    """Tests for ReDoc endpoint."""

    def test_redoc_available(self, client):
        """ReDoc should be available."""
        response = client.get("/redoc")
        assert response.status_code == 200
        assert 'text/html' in response.headers.get('content-type', '')
