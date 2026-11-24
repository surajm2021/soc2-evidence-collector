import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    """Make sure tests can never reach a real account."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")
