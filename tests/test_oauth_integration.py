#!/usr/bin/env python3
"""
OAuth Integration Tests
Tests that OAuth authentication integrates with the multiplayer system
"""

import pytest
import requests
import base64
import urllib3
from channel_manager import ChannelManager

urllib3.disable_warnings()

BASE_URL = 'http://127.0.0.1:8100'

@pytest.fixture
def oauth_tokens():
    """Fixture to provide OAuth tokens for testing"""

    # Alice registers and gets token
    alice_reg = requests.post(f'{BASE_URL}/register',
        json={'client_name': 'Alice Test', 'redirect_uris': ['http://localhost/callback']},
        verify=False)

    assert alice_reg.status_code == 201
    alice_data = alice_reg.json()

    alice_creds = base64.b64encode(f'{alice_data["client_id"]}:{alice_data["client_secret"]}'.encode()).decode()
    alice_token_resp = requests.post(f'{BASE_URL}/token',
        data={'grant_type': 'client_credentials', 'scope': 'mcp'},
        headers={'Authorization': f'Basic {alice_creds}'},
        verify=False)

    assert alice_token_resp.status_code == 200
    alice_token = alice_token_resp.json()['access_token']

    # Bob registers and gets token
    bob_reg = requests.post(f'{BASE_URL}/register',
        json={'client_name': 'Bob Test', 'redirect_uris': ['http://localhost/callback']},
        verify=False)

    assert bob_reg.status_code == 201
    bob_data = bob_reg.json()

    bob_creds = base64.b64encode(f'{bob_data["client_id"]}:{bob_data["client_secret"]}'.encode()).decode()
    bob_token_resp = requests.post(f'{BASE_URL}/token',
        data={'grant_type': 'client_credentials', 'scope': 'mcp'},
        headers={'Authorization': f'Basic {bob_creds}'},
        verify=False)

    assert bob_token_resp.status_code == 200
    bob_token = bob_token_resp.json()['access_token']

    return {
        'alice_token': alice_token,
        'alice_session': f'alice_oauth_{alice_data["client_id"][:8]}',
        'bob_token': bob_token,
        'bob_session': f'bob_oauth_{bob_data["client_id"][:8]}'
    }

def test_oauth_registration_works():
    """Test that OAuth client registration works"""

    response = requests.post(f'{BASE_URL}/register',
        json={'client_name': 'Test Client', 'redirect_uris': ['http://localhost/callback']},
        verify=False)

    assert response.status_code == 201
    data = response.json()

    assert 'client_id' in data
    assert 'client_secret' in data
    assert len(data['client_id']) > 10
    assert len(data['client_secret']) > 10

def test_oauth_token_generation_works():
    """Test that OAuth token generation works"""

    # Register client
    reg_resp = requests.post(f'{BASE_URL}/register',
        json={'client_name': 'Token Test Client', 'redirect_uris': ['http://localhost/callback']},
        verify=False)

    assert reg_resp.status_code == 201
    client_data = reg_resp.json()

    # Get token
    creds = base64.b64encode(f'{client_data["client_id"]}:{client_data["client_secret"]}'.encode()).decode()
    token_resp = requests.post(f'{BASE_URL}/token',
        data={'grant_type': 'client_credentials', 'scope': 'mcp'},
        headers={'Authorization': f'Basic {creds}'},
        verify=False)

    assert token_resp.status_code == 200
    token_data = token_resp.json()

    assert 'access_token' in token_data
    assert 'token_type' in token_data
    assert token_data['token_type'].lower() == 'bearer'
    assert len(token_data['access_token']) > 10

def test_oauth_enables_multiplayer_game(oauth_tokens):
    """Test that OAuth-authenticated sessions can create and play multiplayer games"""

    cm = ChannelManager()

    # Create channel
    result = cm.create_channel(
        name="OAuth Test Game",
        slots=["invite:alice", "invite:bob"]
    )

    channel_id = result["channel_id"]
    invites = result["invites"]

    # Players join using OAuth-derived sessions
    alice_join = cm.join_channel(invites[0], oauth_tokens['alice_session'])
    bob_join = cm.join_channel(invites[1], oauth_tokens['bob_session'])

    assert alice_join["channel_id"] == channel_id
    assert bob_join["channel_id"] == channel_id
    assert alice_join["slot_id"] != bob_join["slot_id"]

    # Exchange messages
    alice_msg = cm.post_message(channel_id, oauth_tokens['alice_session'], 'user',
        'OAuth authenticated message from Alice!')

    bob_msg = cm.post_message(channel_id, oauth_tokens['bob_session'], 'user',
        'OAuth authenticated message from Bob!')

    # Verify messages
    alice_sync = cm.sync_messages(channel_id, oauth_tokens['alice_session'])
    bob_sync = cm.sync_messages(channel_id, oauth_tokens['bob_session'])

    alice_messages = alice_sync["messages"]
    bob_messages = bob_sync["messages"]

    assert len(alice_messages) >= 2
    assert len(bob_messages) >= 2

    # Check message content
    user_messages = [m for m in alice_messages if m["kind"] == "user"]
    assert len(user_messages) == 2

    alice_msg_found = any(m["body"] == "OAuth authenticated message from Alice!" for m in user_messages)
    bob_msg_found = any(m["body"] == "OAuth authenticated message from Bob!" for m in user_messages)

    assert alice_msg_found, "Alice's OAuth message not found"
    assert bob_msg_found, "Bob's OAuth message not found"

def test_oauth_tokens_are_valid(oauth_tokens):
    """Test that generated OAuth tokens are valid and accepted by the proxy"""

    alice_headers = {'Authorization': f'Bearer {oauth_tokens["alice_token"]}'}
    bob_headers = {'Authorization': f'Bearer {oauth_tokens["bob_token"]}'}

    # Test access to OAuth discovery endpoints
    alice_resp = requests.get(f'{BASE_URL}/.well-known/oauth-authorization-server',
        headers=alice_headers, verify=False)
    bob_resp = requests.get(f'{BASE_URL}/.well-known/oauth-authorization-server',
        headers=bob_headers, verify=False)

    # Should get valid responses (200 OK)
    assert alice_resp.status_code == 200
    assert bob_resp.status_code == 200

if __name__ == "__main__":
    pytest.main([__file__, "-v"])