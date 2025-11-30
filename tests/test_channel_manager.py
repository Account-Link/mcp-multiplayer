#!/usr/bin/env python3
"""
Tests for Channel Manager
"""

import pytest
from channel_manager import ChannelManager, Slot, Message, ChannelView

class TestChannelCreation:
    def test_create_basic_channel(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test Channel",
            slots=["invite:player1", "invite:player2"]
        )

        assert "channel_id" in result
        assert len(result["invites"]) == 2
        assert result["view"].name == "Test Channel"
        assert len(result["view"].slots) == 2

        # Check slots are properly configured
        slots = result["view"].slots
        assert slots[0]["kind"] == "invite"
        assert slots[0]["label"] == "player1"
        assert slots[0]["filled_by"] is None
        assert slots[1]["kind"] == "invite"
        assert slots[1]["label"] == "player2"

    def test_create_channel_with_bot(self):
        cm = ChannelManager()

        bot_def = {
            "slot": "bot:referee",
            "name": "GuessBot",
            "version": "1.0",
            "manifest": {"summary": "Guessing game referee"}
        }

        result = cm.create_channel(
            name="Game Channel",
            slots=["bot:referee", "invite:player1", "invite:player2"],
            bots=[bot_def]
        )

        slots = result["view"].slots
        assert len(slots) == 3
        assert slots[0]["kind"] == "bot"
        assert slots[0]["filled_by"] == "bot:GuessBot"
        assert slots[0]["admin"] is True

        # Check system message was posted
        channel_id = result["channel_id"]
        channel = cm.channels[channel_id]
        assert len(channel["messages"]) == 1
        msg = channel["messages"][0]
        assert msg.kind == "system"
        assert msg.body["type"] == "bots_announced"

    def test_invite_codes_generated(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:p1", "invite:p2", "bot:ref"]
        )

        # Should have 2 invite codes (not one for bot slot)
        assert len(result["invites"]) == 2

        # Invite codes should be in manager
        for invite_code in result["invites"]:
            assert invite_code in cm.invites
            invite_info = cm.invites[invite_code]
            assert invite_info["channel_id"] == result["channel_id"]

class TestChannelJoining:
    def test_join_with_valid_invite(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1", "invite:player2"]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        join_result = cm.join_channel(invite_code, "sess_123")

        assert join_result["channel_id"] == channel_id
        assert join_result["slot_id"] in ["s0", "s1"]

        # Check slot is now filled
        view = join_result["view"]
        filled_slot = next(s for s in view.slots if s["filled_by"] == "sess_123")
        assert filled_slot is not None

        # Invite code should be consumed
        assert invite_code not in cm.invites

        # Session should be tracked
        assert "sess_123" in cm.session_slots

    def test_join_with_invalid_invite(self):
        cm = ChannelManager()

        with pytest.raises(ValueError, match="INVITE_INVALID"):
            cm.join_channel("invalid_invite", "sess_123")

    def test_join_already_filled_slot(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        invite_code = result["invites"][0]

        # First join succeeds
        cm.join_channel(invite_code, "sess_123")

        # Second join with different session should fail
        with pytest.raises(ValueError, match="INVITE_INVALID"):
            cm.join_channel(invite_code, "sess_456")

    def test_join_idempotent_same_session(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        invite_code = result["invites"][0]

        # First join
        join1 = cm.join_channel(invite_code, "sess_123")

        # Manually re-add invite to test idempotency
        cm.invites[invite_code] = {
            "channel_id": join1["channel_id"],
            "slot_id": join1["slot_id"]
        }

        # Second join with same session should succeed
        join2 = cm.join_channel(invite_code, "sess_123")
        assert join1["channel_id"] == join2["channel_id"]
        assert join1["slot_id"] == join2["slot_id"]

class TestMessaging:
    def test_post_message_valid_member(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        cm.join_channel(invite_code, "sess_123")

        post_result = cm.post_message(
            channel_id, "sess_123", "user",
            {"type": "test", "content": "hello"}
        )

        assert "msg_id" in post_result
        assert "ts" in post_result

        # Check message was stored
        messages = cm.channels[channel_id]["messages"]
        user_messages = [m for m in messages if m.kind == "user"]
        assert len(user_messages) == 1
        assert user_messages[0].sender == "sess_123"
        assert user_messages[0].body["content"] == "hello"

    def test_post_message_non_member(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        channel_id = result["channel_id"]

        with pytest.raises(ValueError, match="NOT_MEMBER"):
            cm.post_message(
                channel_id, "sess_unknown", "user",
                {"type": "test"}
            )

    def test_post_message_invalid_channel(self):
        cm = ChannelManager()

        with pytest.raises(ValueError, match="CHANNEL_NOT_FOUND"):
            cm.post_message(
                "invalid_channel", "sess_123", "user",
                {"type": "test"}
            )

class TestMessageSync:
    def test_sync_messages_from_start(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        cm.join_channel(invite_code, "sess_123")

        # Post some messages
        cm.post_message(channel_id, "sess_123", "user", {"msg": "first"})
        cm.post_message(channel_id, "sess_123", "user", {"msg": "second"})

        # Sync from start
        sync_result = cm.sync_messages(channel_id, "sess_123", cursor=None)

        assert "messages" in sync_result
        assert "cursor" in sync_result

        # Should include system message + 2 user messages
        messages = sync_result["messages"]
        assert len(messages) >= 2

        user_messages = [m for m in messages if m["kind"] == "user"]
        assert len(user_messages) == 2
        assert user_messages[0]["body"]["msg"] == "first"
        assert user_messages[1]["body"]["msg"] == "second"

    def test_sync_messages_with_cursor(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        cm.join_channel(invite_code, "sess_123")

        # Get current state
        sync1 = cm.sync_messages(channel_id, "sess_123")
        cursor = sync1["cursor"]

        # Post new message
        cm.post_message(channel_id, "sess_123", "user", {"msg": "new"})

        # Sync with cursor
        sync2 = cm.sync_messages(channel_id, "sess_123", cursor=cursor)

        # Should only get new messages
        new_messages = sync2["messages"]
        assert len(new_messages) == 1
        assert new_messages[0]["body"]["msg"] == "new"

    def test_sync_messages_non_member(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        channel_id = result["channel_id"]

        with pytest.raises(ValueError, match="NOT_MEMBER"):
            cm.sync_messages(channel_id, "sess_unknown")

class TestAdminOperations:
    def test_update_channel_non_admin(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1", "invite:player2"]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        cm.join_channel(invite_code, "sess_123")

        with pytest.raises(ValueError, match="NOT_ADMIN"):
            cm.update_channel(channel_id, "sess_123", [
                {"type": "rename", "name": "New Name"}
            ])

    def test_update_channel_rename(self):
        cm = ChannelManager()

        bot_def = {
            "slot": "bot:admin",
            "name": "AdminBot",
            "manifest": {"summary": "Admin bot"}
        }

        result = cm.create_channel(
            name="Test",
            slots=["bot:admin", "invite:player1"],
            bots=[bot_def]
        )

        channel_id = result["channel_id"]

        # Simulate bot session (bots have admin by default)
        # For testing, we'll manually set up bot session
        cm.session_slots["bot:AdminBot"] = {
            "channel_id": channel_id,
            "slot_id": "s0"
        }

        update_result = cm.update_channel(channel_id, "bot:AdminBot", [
            {"type": "rename", "name": "New Name"}
        ])

        assert update_result["ok"] is True
        assert update_result["view"].name == "New Name"

        # Check system message posted
        messages = cm.channels[channel_id]["messages"]
        system_messages = [m for m in messages if m.kind == "system" and
                          m.body.get("type") == "rename_applied"]
        assert len(system_messages) == 1

    def test_update_channel_set_admin(self):
        cm = ChannelManager()

        bot_def = {
            "slot": "bot:admin",
            "name": "AdminBot",
            "manifest": {"summary": "Admin bot"}
        }

        result = cm.create_channel(
            name="Test",
            slots=["bot:admin", "invite:player1"],
            bots=[bot_def]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        # Join as player
        cm.join_channel(invite_code, "sess_123")

        # Setup bot session for admin operations
        cm.session_slots["bot:AdminBot"] = {
            "channel_id": channel_id,
            "slot_id": "s0"
        }

        # Promote player to admin
        cm.update_channel(channel_id, "bot:AdminBot", [
            {"type": "set_admin", "slot_id": "s1", "admin": True}
        ])

        # Check player is now admin
        channel = cm.channels[channel_id]
        player_slot = next(s for s in channel["slots"] if s.slot_id == "s1")
        assert player_slot.admin is True

class TestMembershipChecks:
    def test_is_member_valid(self):
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1"]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        cm.join_channel(invite_code, "sess_123")

        assert cm._is_member(channel_id, "sess_123") is True
        assert cm._is_member(channel_id, "sess_unknown") is False

    def test_is_admin_valid(self):
        cm = ChannelManager()

        bot_def = {
            "slot": "bot:admin",
            "name": "AdminBot",
            "manifest": {"summary": "Admin bot"}
        }

        result = cm.create_channel(
            name="Test",
            slots=["bot:admin", "invite:player1"],
            bots=[bot_def]
        )

        channel_id = result["channel_id"]
        invite_code = result["invites"][0]

        cm.join_channel(invite_code, "sess_123")

        # Setup bot session
        cm.session_slots["bot:AdminBot"] = {
            "channel_id": channel_id,
            "slot_id": "s0"
        }

        assert cm._is_admin(channel_id, "bot:AdminBot") is True
        assert cm._is_admin(channel_id, "sess_123") is False


class TestPrivateMessages:
    def test_message_to_slot_field(self):
        """Test Message dataclass has to_slot field."""
        msg = Message(
            id=1,
            channel_id="chn_test",
            sender="sess_123",
            kind="user",
            body={"text": "hello"},
            ts="2024-01-01T00:00:00",
            to_slot="s1"
        )
        assert msg.to_slot == "s1"

        # Default should be None
        msg_public = Message(
            id=2,
            channel_id="chn_test",
            sender="sess_123",
            kind="user",
            body={"text": "public"},
            ts="2024-01-01T00:00:00"
        )
        assert msg_public.to_slot is None

    def test_post_private_message(self):
        """Test posting a private message sets to_slot."""
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1", "invite:player2"]
        )

        channel_id = result["channel_id"]

        # Post a private message
        post_result = cm.post_private_message(
            channel_id=channel_id,
            sender="bot:TestBot",
            to_slot="s0",
            kind="private",
            body={"text": "secret message"}
        )

        assert "msg_id" in post_result
        assert "ts" in post_result

        # Check message was stored with to_slot
        messages = cm.channels[channel_id]["messages"]
        private_msg = next(m for m in messages if m.kind == "private")
        assert private_msg.to_slot == "s0"
        assert private_msg.sender == "bot:TestBot"
        assert private_msg.body["text"] == "secret message"

    def test_sync_filters_private_messages(self):
        """Test sync_messages filters by to_slot - player only sees their messages."""
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1", "invite:player2"]
        )

        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        # Both players join
        cm.join_channel(invite1, "sess_alice")  # slot s0
        cm.join_channel(invite2, "sess_bob")    # slot s1

        # Post a public message
        cm.post_message(channel_id, "sess_alice", "user", {"text": "public hello"})

        # Post a private message to Alice (s0)
        cm.post_private_message(
            channel_id=channel_id,
            sender="bot:TestBot",
            to_slot="s0",
            kind="private",
            body={"text": "secret for alice"}
        )

        # Post a private message to Bob (s1)
        cm.post_private_message(
            channel_id=channel_id,
            sender="bot:TestBot",
            to_slot="s1",
            kind="private",
            body={"text": "secret for bob"}
        )

        # Alice syncs - should see public + her private
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        alice_msgs = alice_sync["messages"]
        alice_private = [m for m in alice_msgs if m.get("to_slot") == "s0"]
        alice_bob_private = [m for m in alice_msgs if m.get("to_slot") == "s1"]

        assert len(alice_private) == 1
        assert alice_private[0]["body"]["text"] == "secret for alice"
        assert len(alice_bob_private) == 0  # Alice can't see Bob's private messages

        # Bob syncs - should see public + his private
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        bob_msgs = bob_sync["messages"]
        bob_private = [m for m in bob_msgs if m.get("to_slot") == "s1"]
        bob_alice_private = [m for m in bob_msgs if m.get("to_slot") == "s0"]

        assert len(bob_private) == 1
        assert bob_private[0]["body"]["text"] == "secret for bob"
        assert len(bob_alice_private) == 0  # Bob can't see Alice's private messages

    def test_sync_shows_public_messages(self):
        """Test sync_messages shows public messages (to_slot=None) to everyone."""
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1", "invite:player2"]
        )

        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Post public messages
        cm.post_message(channel_id, "sess_alice", "user", {"text": "hi from alice"})
        cm.post_message(channel_id, "sess_bob", "user", {"text": "hi from bob"})

        # Both should see all public messages
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        bob_sync = cm.sync_messages(channel_id, "sess_bob")

        alice_user_msgs = [m for m in alice_sync["messages"] if m["kind"] == "user"]
        bob_user_msgs = [m for m in bob_sync["messages"] if m["kind"] == "user"]

        assert len(alice_user_msgs) == 2
        assert len(bob_user_msgs) == 2

    def test_get_slot_id_for_session(self):
        """Test get_slot_id_for_session helper."""
        cm = ChannelManager()

        result = cm.create_channel(
            name="Test",
            slots=["invite:player1", "invite:player2"]
        )

        channel_id = result["channel_id"]
        invite1 = result["invites"][0]

        # Before joining, should return None
        assert cm.get_slot_id_for_session(channel_id, "sess_alice") is None

        # After joining, should return slot_id
        join_result = cm.join_channel(invite1, "sess_alice")
        assert cm.get_slot_id_for_session(channel_id, "sess_alice") == join_result["slot_id"]

        # Unknown session should return None
        assert cm.get_slot_id_for_session(channel_id, "sess_unknown") is None

        # Unknown channel should return None
        assert cm.get_slot_id_for_session("unknown_channel", "sess_alice") is None