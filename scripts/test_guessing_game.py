#!/usr/bin/env python3
"""
Test guessing game functionality with two players using shared MCPClient
"""

import sys
import os
import json

# Add the scripts directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(__file__))

from mcp_client import MCPClient
from config import print_config

def test_guessing_game():
    """Test complete guessing game flow with two players"""
    print_config()
    print()
    print("Testing MCP guessing game functionality...")
    print("=" * 60)

    try:
        # Connect two clients for Alice and Bob
        print("\n🔐 Setting up two players...")
        alice = MCPClient()
        alice.client_name = "Alice Player"
        alice.token_file = "alice_tokens.json"  # Separate token files
        alice = alice.connect()
        print("✅ Alice connected")

        bob = MCPClient()
        bob.client_name = "Bob Player"
        bob.token_file = "bob_tokens.json"  # Separate token files
        bob = bob.connect()
        print("✅ Bob connected")

        print("\n🎮 Creating guessing game channel...")
        create_resp = alice.call_tool("create_channel", {
            "name": "Test Guessing Game",
            "slots": ["bot:guess-referee", "invite:alice", "invite:bob"],
            "bot_preset": "GuessBot"
        })

        channel_id = create_resp["channel_id"]
        invites = create_resp["invites"]
        print(f"✅ Created channel: {channel_id}")
        print(f"   Alice invite: {invites[0]}")
        print(f"   Bob invite: {invites[1]}")

        print("\n👥 Both players joining...")
        alice_join = alice.call_tool("join_channel", {"invite_code": invites[0]})
        print(f"✅ Alice joined as slot: {alice_join.get('slot_id')}")

        bob_join = bob.call_tool("join_channel", {"invite_code": invites[1]})
        print(f"✅ Bob joined as slot: {bob_join.get('slot_id')}")

        print("\n📥 Checking initial game state...")
        sync_resp = alice.call_tool("sync_messages", {"channel_id": channel_id})
        messages = sync_resp.get("messages", [])
        print(f"✅ Found {len(messages)} initial messages")

        # Show important messages (bot initialization, game setup)
        for msg in messages:
            sender = msg['sender'][:12]
            body = msg.get('body', {})
            if 'players' in str(body) or 'GuessBot' in sender or 'game' in str(body).lower():
                print(f"   🤖 {sender}: {body}")

        print("\n🎯 Alice makes first guess: 50")
        # Note: post_message now only accepts simple text. For game moves with structured data,
        # the bot would need to be updated to parse JSON from text, or moves need to be done programmatically.
        alice_guess = alice.call_tool("post_message", {
            "channel_id": channel_id,
            "body": "guess 50"
        })
        print(f"✅ Alice's guess posted: {alice_guess.get('msg_id')}")

        print("\n📥 Checking bot response...")
        sync_resp2 = alice.call_tool("sync_messages", {"channel_id": channel_id})
        new_messages = sync_resp2.get("messages", [])

        # Show only new messages since last sync
        recent_messages = new_messages[len(messages):]
        print(f"✅ {len(recent_messages)} new messages since guess")
        for msg in recent_messages:
            sender = msg['sender'][:12]
            body = msg.get('body', {})
            print(f"   📨 {sender} ({msg['kind']}): {body}")

        # Look for bot feedback (high/low/correct)
        bot_responded = any(msg.get('kind') == 'bot' and msg.get('body', {}).get('type') == 'judge'
                           for msg in recent_messages)

        if bot_responded:
            print("🎉 GuessBot is working! It responded to Alice's guess.")

            print("\n🎯 Bob makes a guess: 25")
            bob_guess = bob.call_tool("post_message", {
                "channel_id": channel_id,
                "body": "guess 25"
            })

            print("\n📥 Final game state...")
            final_sync = alice.call_tool("sync_messages", {"channel_id": channel_id})
            final_messages = final_sync.get("messages", [])

            # Show last few messages
            print(f"✅ Total game messages: {len(final_messages)}")
            print("   📋 Recent game activity:")
            for msg in final_messages[-5:]:
                sender = msg['sender'][:12]
                body = msg.get('body', {})
                print(f"      {sender} ({msg['kind']}): {body}")

        else:
            print("⚠️  GuessBot didn't respond as expected to Alice's guess")

        print("\n" + "=" * 60)
        print("✅ Guessing game test completed!")

    except Exception as e:
        print(f"❌ Error during guessing game test: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

def main():
    return test_guessing_game()

if __name__ == "__main__":
    sys.exit(main())