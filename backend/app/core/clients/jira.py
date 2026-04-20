"""
Jira REST API v3 client — creates remediation issues.

Authentication: Bearer token (Jira Cloud API token).
Jira's Atlassian Document Format (ADF) is used for the description field.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("vulnops.jira")


async def create_jira_issue(
    base_url: str,
    project_key: str,
    api_key: str,
    *,
    summary: str,
    description: str,
    priority: str = "Medium",
    issue_type: str = "Task",
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """
    Create a Jira issue via REST API v3.

    Args:
        base_url: Jira instance URL (e.g. https://myorg.atlassian.net).
        project_key: Jira project key (e.g. SEC).
        api_key: Jira API token — sent as Bearer auth.
        summary: Issue title (max 255 chars for Jira).
        description: Issue body (plain text, converted to ADF paragraph).
        priority: Jira priority name (Highest, High, Medium, Low).
        issue_type: Jira issue type name (Task, Bug, Story, etc.).
        http_client: Optional pre-configured client for testing.

    Returns:
        dict with keys: key (e.g. "SEC-123"), id, url.

    Raises:
        httpx.HTTPStatusError: on 4xx/5xx responses from Jira.
        httpx.RequestError: on network/connection errors.
    """
    url = f"{base_url.rstrip('/')}/rest/api/3/issue"

    # Jira ADF (Atlassian Document Format) for the description field
    adf_description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": description}],
            }
        ],
    }

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:255],
            "description": adf_description,
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
        }
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    _own_client = http_client is None
    _client = http_client or httpx.AsyncClient(timeout=15.0)
    try:
        resp = await _client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        issue_key = data.get("key", "")
        issue_id = data.get("id", "")
        issue_url = f"{base_url.rstrip('/')}/browse/{issue_key}"
        logger.info("Created Jira issue %s at %s", issue_key, issue_url)
        return {"key": issue_key, "id": issue_id, "url": issue_url}
    finally:
        if _own_client:
            await _client.aclose()
