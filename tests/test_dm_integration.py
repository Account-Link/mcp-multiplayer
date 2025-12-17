#!/usr/bin/env python3
"""
Integration tests for Private DM functionality
"""

import pytest
from channel_manager import ChannelManager
from bot_manager import BotManager, BotDefinition


class TestDMIntegration:
    def test_full_dm_flow(self):
        """Test complete DM flow: player DMs bot, bot responds privately."""
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create channel with GuessBot
        result = cm.create_channel("Test Game", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        # Attach GuessBot
        bot_def = BotDefinition(
            name="GuessBot",
            version="1.0",
            code_ref="builtin://GuessBot",
            manifest={
                "summary": "Guessing game referee",
                "hooks": ["on_init", "on_join", "on_message", "on_private_message"],
                "params": {"mode": "number", "range": [1, 100]}
            }
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Players join
        cm.join_channel(invite1, "sess_alice")  # slot s0
        cm.join_channel(invite2, "sess_bob")    # slot s1

        # Dispatch join events to bot
        bm.dispatch_join(channel_id, "sess_alice")
        bm.dispatch_join(channel_id, "sess_bob")

        # Alice sends a private DM to the bot
        dm_message = {"text": "!status"}
        bm.dispatch_private_message(channel_id, bot_id, "s0", dm_message)

        # Sync messages for Alice - should see the private response
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        alice_msgs = alice_sync["messages"]

        # Find private messages addressed to Alice (s0)
        alice_private = [m for m in alice_msgs if m.get("to_slot") == "s0"]

        # Should have at least one private response with status info
        assert len(alice_private) >= 1
        status_response = alice_private[-1]
        assert status_response["kind"] == "private"
        assert "game_started" in status_response["body"]

    def test_other_player_cannot_see_dm_response(self):
        """Test that player B cannot see DM response sent to player A."""
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create channel
        result = cm.create_channel("Test Game", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        # Attach GuessBot
        bot_def = BotDefinition(
            name="GuessBot",
            version="1.0",
            code_ref="builtin://GuessBot",
            manifest={
                "summary": "Guessing game referee",
                "hooks": ["on_init", "on_join", "on_message", "on_private_message"],
                "params": {"mode": "number", "range": [1, 100]}
            }
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Players join
        cm.join_channel(invite1, "sess_alice")  # slot s0
        cm.join_channel(invite2, "sess_bob")    # slot s1

        # Dispatch join events
        bm.dispatch_join(channel_id, "sess_alice")
        bm.dispatch_join(channel_id, "sess_bob")

        # Get initial cursor for both players
        alice_initial = cm.sync_messages(channel_id, "sess_alice")
        bob_initial = cm.sync_messages(channel_id, "sess_bob")
        alice_cursor = alice_initial["cursor"]
        bob_cursor = bob_initial["cursor"]

        # Alice sends a private DM to the bot
        dm_message = {"text": "!status"}
        bm.dispatch_private_message(channel_id, bot_id, "s0", dm_message)

        # Sync for Alice - should see her private response
        alice_sync = cm.sync_messages(channel_id, "sess_alice", cursor=alice_cursor)
        alice_new_msgs = alice_sync["messages"]
        alice_private = [m for m in alice_new_msgs if m.get("to_slot") == "s0"]
        assert len(alice_private) >= 1

        # Sync for Bob - should NOT see Alice's private response
        bob_sync = cm.sync_messages(channel_id, "sess_bob", cursor=bob_cursor)
        bob_new_msgs = bob_sync["messages"]
        bob_sees_alice_private = [m for m in bob_new_msgs if m.get("to_slot") == "s0"]
        assert len(bob_sees_alice_private) == 0

    def test_private_message_with_custom_bot(self):
        """Test private messaging with a custom inline bot."""
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create channel
        result = cm.create_channel("Custom Bot Test", ["invite:player1"])
        channel_id = result["channel_id"]
        invite1 = result["invites"][0]

        # Define a custom bot that responds to private messages
        inline_code = '''
class EchoPrivateBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
        self.params = params

    def on_init(self):
        self.ctx.post("bot", {"type": "ready", "message": "EchoPrivateBot initialized"})

    def on_private_message(self, slot_id, msg):
        text = msg.get("text", "")
        # Echo back privately
        self.ctx.dm(slot_id, "private", {
            "type": "echo",
            "original": text,
            "response": f"You said: {text}"
        })
'''

        bot_def = BotDefinition(
            name="EchoPrivateBot",
            version="1.0",
            inline_code=inline_code,
            manifest={
                "summary": "Echoes private messages",
                "hooks": ["on_init", "on_private_message"]
            }
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Player joins
        cm.join_channel(invite1, "sess_alice")  # slot s0

        # Get initial cursor
        initial_sync = cm.sync_messages(channel_id, "sess_alice")
        cursor = initial_sync["cursor"]

        # Alice sends a private DM
        dm_message = {"text": "Hello secret bot!"}
        bm.dispatch_private_message(channel_id, bot_id, "s0", dm_message)

        # Sync and check response
        alice_sync = cm.sync_messages(channel_id, "sess_alice", cursor=cursor)
        alice_msgs = alice_sync["messages"]

        # Find the private echo response
        private_responses = [m for m in alice_msgs if m.get("to_slot") == "s0"]
        assert len(private_responses) >= 1

        echo_response = private_responses[-1]
        assert echo_response["body"]["type"] == "echo"
        assert echo_response["body"]["original"] == "Hello secret bot!"
        assert "You said:" in echo_response["body"]["response"]

    def test_public_and_private_messages_coexist(self):
        """Test that public and private messages work together correctly."""
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create channel
        result = cm.create_channel("Mixed Messages", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        # Attach GuessBot
        bot_def = BotDefinition(
            name="GuessBot",
            version="1.0",
            code_ref="builtin://GuessBot",
            manifest={"hooks": ["on_init", "on_join", "on_message", "on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Players join
        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")
        bm.dispatch_join(channel_id, "sess_alice")
        bm.dispatch_join(channel_id, "sess_bob")

        # Post a public message from Alice
        cm.post_message(channel_id, "sess_alice", "user", {"text": "Hello everyone!"})

        # Alice sends a private DM
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "!status"})

        # Bob posts a public message
        cm.post_message(channel_id, "sess_bob", "user", {"text": "Hi Alice!"})

        # Alice syncs - should see public messages + her private response
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        alice_msgs = alice_sync["messages"]

        alice_public = [m for m in alice_msgs if m.get("to_slot") is None and m["kind"] == "user"]
        alice_private = [m for m in alice_msgs if m.get("to_slot") == "s0"]

        assert len(alice_public) == 2  # Her message + Bob's message
        assert len(alice_private) >= 1  # Her private response

        # Bob syncs - should see public messages but NOT Alice's private response
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        bob_msgs = bob_sync["messages"]

        bob_public = [m for m in bob_msgs if m.get("to_slot") is None and m["kind"] == "user"]
        bob_alice_private = [m for m in bob_msgs if m.get("to_slot") == "s0"]

        assert len(bob_public) == 2  # Both public messages
        assert len(bob_alice_private) == 0  # Cannot see Alice's private messages

