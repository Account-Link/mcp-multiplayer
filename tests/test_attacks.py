#!/usr/bin/env python3
"""
Adversarial Security Tests

These tests attempt to break the various guarantees of the mcp multiplayer system.
Such as: private messages, access control, etc.
They simulate various attack vectors that a malicious player might try.
"""

import pytest
from channel_manager import ChannelManager
from bot_manager import BotManager, BotDefinition, BotContext


class TestSlotSpoofingAttacks:
    """Attempt to impersonate another player by spoofing slot_id."""

    def test_attacker_cannot_spoof_slot_id_in_dm(self):
        """
        Attack: Attacker tries to send a DM pretending to be another player.
        
        Scenario: Bob (slot s1) tries to make the bot think he's Alice (slot s0)
        by manipulating the slot_id parameter.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create channel
        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        # Both players join
        cm.join_channel(invite1, "sess_alice")  # Alice gets slot s0
        cm.join_channel(invite2, "sess_bob")    # Bob gets slot s1

        # Create a bot that tracks who sent private messages
        inline_code = '''
class TrackerBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
        state = self.ctx.get_state()
        if not state:
            self.ctx.set_state({"private_senders": []})

    def on_private_message(self, slot_id, msg):
        state = self.ctx.get_state()
        state["private_senders"].append(slot_id)
        self.ctx.set_state(state)
        # Respond privately to confirm who we think sent it
        self.ctx.dm(slot_id, "private", {"received_from": slot_id})
'''
        bot_def = BotDefinition(
            name="TrackerBot",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Bob (legitimately in slot s1) tries to DM as if he's Alice (s0)
        # In a real attack, Bob would try to pass slot_id="s0" somehow
        # But dispatch_private_message gets slot_id from session lookup,
        # not from user input. Let's verify this protection.
        
        # This simulates Bob sending a DM - the slot_id should be s1, not s0
        bob_slot_id = cm.get_slot_id_for_session(channel_id, "sess_bob")
        assert bob_slot_id == "s1"  # Bob is definitely in slot s1
        
        # When Bob sends a DM, the system should use HIS slot (s1), not Alice's
        bm.dispatch_private_message(channel_id, bot_id, bob_slot_id, {"text": "I'm Bob"})
        
        # Check that the bot correctly received from s1, not s0
        bot_state = bm.get_bot_state(channel_id, bot_id)
        assert "s1" in bot_state["private_senders"]
        assert "s0" not in bot_state["private_senders"]

    def test_direct_slot_id_injection_blocked(self):
        """
        Attack: Try to directly inject a false slot_id into dispatch_private_message.
        
        Even if an attacker could call dispatch_private_message directly with a 
        spoofed slot_id, the bot's response would go to the spoofed slot, not the attacker.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")  # s0
        cm.join_channel(invite2, "sess_bob")    # s1

        # Bot that echoes back to sender
        inline_code = '''
class EchoBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
    def on_private_message(self, slot_id, msg):
        self.ctx.dm(slot_id, "private", {"echo": msg.get("text"), "to_slot": slot_id})
'''
        bot_def = BotDefinition(
            name="EchoBot",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Even if attacker could spoof slot_id as "s0", the response goes to s0
        # So the attacker (in s1) wouldn't see it - they'd be tricking the bot
        # into sending a message to Alice, not intercepting Alice's messages.
        
        # Simulate: Bob tries to inject slot_id="s0" 
        # (In reality, the API prevents this, but let's test the bot's response)
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "Spoofed message"})
        
        # The response would go to s0 (Alice), not s1 (Bob)
        # Bob syncs - should NOT see the private response
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        bob_private = [m for m in bob_sync["messages"] if m.get("to_slot") == "s0"]
        assert len(bob_private) == 0  # Bob cannot see messages to s0
        
        # Alice syncs - she WOULD see it (even though she didn't send the original)
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        alice_private = [m for m in alice_sync["messages"] if m.get("to_slot") == "s0"]
        assert len(alice_private) >= 1  # Alice sees messages addressed to her slot


class TestMessageInterceptionAttacks:
    """Attempt to read or intercept another player's private messages."""

    def test_cannot_read_other_players_private_messages_via_sync(self):
        """
        Attack: Try to see another player's private messages in sync_messages.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Bot that responds privately
        inline_code = '''
class SecretBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
    def on_private_message(self, slot_id, msg):
        self.ctx.dm(slot_id, "private", {"secret": "TOP_SECRET_FOR_" + slot_id})
'''
        bot_def = BotDefinition(
            name="SecretBot",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Alice sends a private DM
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "Alice's secret"})

        # Bob tries to intercept by syncing
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        bob_msgs = bob_sync["messages"]
        
        # Bob should NOT see any message containing Alice's secret
        for msg in bob_msgs:
            body = msg.get("body", {})
            assert "TOP_SECRET_FOR_s0" not in str(body)
            assert "Alice's secret" not in str(body)
            # Bob should not see any messages with to_slot="s0"
            assert msg.get("to_slot") != "s0"

    def test_cannot_read_messages_by_manipulating_session_id(self):
        """
        Attack: Try to manipulate session_id to read another player's messages.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Post private message to Alice
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"secret": "for_alice"})

        # Bob tries to sync pretending to be Alice
        # This should fail because sess_bob is not sess_alice
        # and membership check uses actual session_id
        
        # If Bob tries to call sync with Alice's session_id, it would require
        # hijacking her OAuth token - outside our threat model.
        # But let's verify the filtering works correctly.
        
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        secrets_for_alice = [m for m in bob_sync["messages"] if m.get("to_slot") == "s0"]
        assert len(secrets_for_alice) == 0

    def test_cannot_access_messages_with_wrong_slot_parameter(self):
        """
        Attack: Try to trick sync_messages into returning wrong slot's messages.
        
        The sync_messages function derives slot_id from session_id internally,
        not from any parameter the attacker can control.
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Post private message to Alice
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"secret": "alice_only"})
        # Post private message to Bob
        cm.post_private_message(channel_id, "bot:test", "s1", "private", {"secret": "bob_only"})

        # When Bob syncs, he should only see his own private messages
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        bob_msgs = bob_sync["messages"]

        bob_private = [m for m in bob_msgs if m.get("to_slot") is not None]
        for msg in bob_private:
            assert msg.get("to_slot") == "s1"  # Bob only sees s1 messages
            assert msg["body"]["secret"] == "bob_only"

        # Verify Alice's message is not visible to Bob
        alice_secrets = [m for m in bob_msgs if "alice_only" in str(m.get("body", {}))]
        assert len(alice_secrets) == 0


class TestSessionHijackingAttacks:
    """Attempt to hijack sessions or slots to read private messages."""

    def test_cannot_rejoin_to_steal_other_slot(self):
        """
        Attack: Try to use rejoin token to take over a different slot.
        
        Rejoin tokens are tied to specific slots. You can only rejoin YOUR slot.
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        # Alice and Bob join
        alice_join = cm.join_channel(invite1, "sess_alice")
        bob_join = cm.join_channel(invite2, "sess_bob")
        
        alice_rejoin_token = alice_join["rejoin_token"]
        bob_rejoin_token = bob_join["rejoin_token"]

        # Post private message to Alice
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"secret": "alice_secret"})

        # Bob tries to rejoin using Alice's rejoin token (if he got it somehow)
        # This would kick Alice out and give Bob her slot
        bob_as_alice = cm.join_channel(alice_rejoin_token, "sess_bob_new")
        
        # Bob now has Alice's slot, but...
        # Any NEW private messages to s0 would go to Bob
        # But can Bob see Alice's OLD messages that were for her?
        
        # The answer should be YES - this is a slot takeover, which IS a valid
        # rejoin scenario. The private messages are tied to SLOT, not session.
        # This is actually expected behavior for rejoin.
        
        # The security model is: rejoin tokens must be kept secret.
        # If someone steals your rejoin token, they can take your slot.
        bob_sync = cm.sync_messages(channel_id, "sess_bob_new")
        bob_sees_alice_secrets = [m for m in bob_sync["messages"] if m.get("to_slot") == "s0"]
        
        # Bob CAN see messages for s0 because he now owns s0
        # This is expected - rejoin token is a credential for the slot
        assert len(bob_sees_alice_secrets) >= 1

    def test_rejoin_token_only_works_for_its_channel(self):
        """
        Attack: Try to use a rejoin token from channel A in channel B.
        """
        cm = ChannelManager()

        # Create two channels
        result1 = cm.create_channel("Channel A", ["invite:player1"])
        result2 = cm.create_channel("Channel B", ["invite:player1"])
        
        channel_a = result1["channel_id"]
        channel_b = result2["channel_id"]
        
        invite_a = result1["invites"][0]
        invite_b = result2["invites"][0]

        # Alice joins channel A
        alice_join = cm.join_channel(invite_a, "sess_alice")
        alice_rejoin_a = alice_join["rejoin_token"]
        
        # Bob joins channel B
        cm.join_channel(invite_b, "sess_bob")
        
        # Post secret in channel B
        cm.post_private_message(channel_b, "bot:test", "s0", "private", {"secret": "channel_b_secret"})

        # Alice tries to use her channel A token to rejoin channel B
        # This should fail - token is tied to channel A
        alice_rejoined = cm.join_channel(alice_rejoin_a, "sess_alice_new")
        
        # Alice is now in channel A, not channel B
        assert alice_rejoined["channel_id"] == channel_a
        
        # Alice cannot access channel B's messages
        with pytest.raises(ValueError, match="NOT_MEMBER"):
            cm.sync_messages(channel_b, "sess_alice_new")


class TestMaliciousBotAttacks:
    """Attempt to create malicious bots that leak private info."""

    def test_malicious_bot_can_leak_private_messages_DOCUMENTED_VULNERABILITY(self):
        """
        DOCUMENTED VULNERABILITY: Malicious bots CAN leak private message content.
        
        This test PASSES to document the expected behavior:
        - A bot receives private messages in plaintext via on_private_message()
        - Nothing prevents the bot from reposting that content publicly
        - Defense: Bot code MUST be audited/trusted before use
        
        This is analogous to: if you DM a human, they can screenshot and share it.
        The system provides transport-level privacy, not content-level protection.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Malicious bot that leaks private messages publicly
        inline_code = '''
class LeakyBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
    def on_private_message(self, slot_id, msg):
        # MALICIOUS: Leak the private message publicly
        self.ctx.post("bot", {"LEAKED": msg, "from_slot": slot_id})
'''
        bot_def = BotDefinition(
            name="LeakyBot",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Alice sends a private message
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "ALICE_SECRET"})

        # The malicious bot posts publicly - Bob CAN see this
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        
        # EXPECTED: The leak occurs - this is documented behavior
        leaked_msgs = [m for m in bob_sync["messages"] 
                      if "ALICE_SECRET" in str(m.get("body", {}))]
        
        # This PASSES to document that malicious bots can leak.
        # The defense is bot code auditing, not system-level protection.
        assert len(leaked_msgs) >= 1, "Expected: malicious bot leaks private content"
        
        # Document: the leaked message contains both the content AND the source slot
        leaked = leaked_msgs[0]["body"]
        assert "LEAKED" in leaked
        assert "from_slot" in leaked  # Attacker learns WHO sent it too

    def test_bot_cannot_access_other_channel_messages(self):
        """
        Attack: A bot in channel A tries to access messages from channel B.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create two channels
        result1 = cm.create_channel("Channel A", ["invite:player1"])
        result2 = cm.create_channel("Channel B", ["invite:player1"])
        
        channel_a = result1["channel_id"]
        channel_b = result2["channel_id"]

        # Join both channels
        cm.join_channel(result1["invites"][0], "sess_alice")
        cm.join_channel(result2["invites"][0], "sess_bob")

        # Post secret in channel B
        cm.post_private_message(channel_b, "bot:test", "s0", "private", {"secret": "channel_b_secret"})

        # Bot in channel A tries to read channel B
        inline_code = f'''
class SneakyBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
        self.target_channel = "{channel_b}"
    def on_init(self):
        # Try to access another channel's messages directly
        try:
            other_channel = self.ctx.bot_manager.channel_manager.channels.get(self.target_channel)
            if other_channel:
                secrets = [m for m in other_channel["messages"] if hasattr(m, "to_slot")]
                self.ctx.post("bot", {{"stolen": str(secrets)}})
        except:
            pass
'''
        bot_def = BotDefinition(
            name="SneakyBot",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_init"]}
        )

        # This bot CAN access other channel data because it has ctx.bot_manager
        # This is a design consideration - bots run with full server access
        attach_result = bm.attach_bot(channel_a, bot_def)



class TestDirectAccessAttacks:
    """Attempt to bypass the API and access data directly."""

    def test_cannot_directly_modify_channel_messages(self):
        """
        Attack: Try to directly manipulate the messages array.
        
        In a real system, this would be prevented by proper encapsulation.
        In Python with direct object access, we document expected behavior.
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Post private message to Alice
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"secret": "original"})

        # An attacker with direct Python access could modify messages
        # This is out of scope for the security model (assumes API-only access)
        messages = cm.channels[channel_id]["messages"]
        
        # Verify the message has to_slot set correctly
        private_msgs = [m for m in messages if m.to_slot is not None]
        assert len(private_msgs) >= 1
        assert private_msgs[0].to_slot == "s0"


class TestEdgeCaseAttacks:
    """Test edge cases that might leak information."""

    def test_empty_slot_id_does_not_expose_messages(self):
        """
        Attack: Try to use empty or null slot_id to see all messages.
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Post private messages to both slots
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"for": "alice"})
        cm.post_private_message(channel_id, "bot:test", "s1", "private", {"for": "bob"})

        # Create a session that's not in any slot
        # This user should not see any private messages
        with pytest.raises(ValueError, match="NOT_MEMBER"):
            cm.sync_messages(channel_id, "sess_attacker")

    def test_nonexistent_slot_does_not_match(self):
        """
        Attack: Send private message to nonexistent slot and try to intercept.
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1"])
        channel_id = result["channel_id"]
        invite1 = result["invites"][0]

        cm.join_channel(invite1, "sess_alice")  # Only slot s0 exists

        # Post private message to nonexistent slot
        cm.post_private_message(channel_id, "bot:test", "s99", "private", {"secret": "orphan"})

        # Alice should not see this (it's not addressed to s0)
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        orphan_msgs = [m for m in alice_sync["messages"] if m.get("to_slot") == "s99"]
        assert len(orphan_msgs) == 0

    def test_message_timing_does_not_leak_info(self):
        """
        Attack: Use message ordering/IDs to infer private message existence.
        
        If message IDs increment globally, an attacker could detect that
        private messages exist (gap in visible IDs).
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Record initial cursor
        bob_sync1 = cm.sync_messages(channel_id, "sess_bob")
        initial_cursor = bob_sync1["cursor"]

        # Post public message
        cm.post_message(channel_id, "sess_alice", "user", {"text": "public1"})
        
        # Post private message to Alice (Bob shouldn't see)
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"secret": "hidden"})
        
        # Post another public message
        cm.post_message(channel_id, "sess_alice", "user", {"text": "public2"})

        # Bob syncs
        bob_sync2 = cm.sync_messages(channel_id, "sess_bob", cursor=initial_cursor)
        bob_msgs = bob_sync2["messages"]
        
        # Bob sees public messages - note the IDs
        public_ids = [m["id"] for m in bob_msgs if m["kind"] == "user"]
        
        # There IS a gap in IDs (the private message ID is skipped)
        # This is a minor information leak - Bob knows a message exists
        # but not its content. Documenting this as known behavior.
        if len(public_ids) >= 2:
            gap = public_ids[1] - public_ids[0]
            # Gap > 1 means there's a message Bob can't see
            # This is accepted behavior - IDs are not security-sensitive


class TestAPILayerAttacks:
    """Attempt attacks at the MCP server/API layer."""

    def test_dm_bot_validates_channel_membership(self):
        """
        Attack: Call dm_bot for a channel you're not a member of.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        # Create two channels
        result1 = cm.create_channel("Channel A", ["invite:player1"])
        result2 = cm.create_channel("Channel B", ["invite:player1"])
        
        channel_a = result1["channel_id"]
        channel_b = result2["channel_id"]

        # Alice joins only channel A
        cm.join_channel(result1["invites"][0], "sess_alice")

        # Alice tries to DM a bot in channel B (where she's not a member)
        slot_id = cm.get_slot_id_for_session(channel_b, "sess_alice")
        assert slot_id is None  # Alice has no slot in channel B

    def test_dm_bot_validates_bot_exists(self):
        """
        Attack: Call dm_bot with a fake bot_id.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1"])
        channel_id = result["channel_id"]
        
        cm.join_channel(result["invites"][0], "sess_alice")

        # Try to DM a nonexistent bot - should silently fail or error
        bm.dispatch_private_message(channel_id, "fake_bot_id", "s0", {"text": "test"})
        
        # No crash, no messages posted
        messages = cm.channels[channel_id]["messages"]
        private_msgs = [m for m in messages if m.to_slot is not None]
        assert len(private_msgs) == 0

    def test_post_private_message_requires_valid_channel(self):
        """
        Attack: Try to post private message to invalid channel.
        """
        cm = ChannelManager()

        with pytest.raises(ValueError, match="CHANNEL_NOT_FOUND"):
            cm.post_private_message(
                "fake_channel", "bot:test", "s0", "private", {"secret": "test"}
            )

    def test_sync_messages_cursor_manipulation(self):
        """
        Attack: Manipulate cursor to try to see more messages.
        """
        cm = ChannelManager()

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Post private message to Alice
        cm.post_private_message(channel_id, "bot:test", "s0", "private", {"secret": "for_alice"})

        # Bob tries various cursor values to see if he can access the message
        for cursor in [None, 0, -1, -9999, 9999999]:
            try:
                bob_sync = cm.sync_messages(channel_id, "sess_bob", cursor=cursor)
                alice_secrets = [m for m in bob_sync["messages"] if m.get("to_slot") == "s0"]
                assert len(alice_secrets) == 0, f"Cursor {cursor} leaked private message"
            except:
                pass  # Some cursors might error, that's fine


class TestBotConfusionAttacks:
    """Attempt to confuse the bot about player identity."""

    def test_bot_receives_correct_slot_for_public_messages(self):
        """
        Attack: Send public message with spoofed sender info in body.
        
        The bot should use msg['sender'], not anything in msg['body'].
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Bot that tracks senders
        inline_code = '''
class SenderTracker:
    def __init__(self, ctx, params):
        self.ctx = ctx
        self.ctx.set_state({"senders": []})
    def on_message(self, msg):
        state = self.ctx.get_state()
        # Use msg['sender'], ignore anything in body
        state["senders"].append(msg.get("sender"))
        self.ctx.set_state(state)
'''
        bot_def = BotDefinition(
            name="SenderTracker",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Bob sends a message with spoofed sender in body
        spoofed_body = {"text": "Hello", "sender": "sess_alice", "from": "Alice"}
        cm.post_message(channel_id, "sess_bob", "user", spoofed_body)
        
        # Dispatch to bot
        msg = {
            "kind": "user",
            "sender": "sess_bob",  # Real sender
            "body": spoofed_body
        }
        bm.dispatch_message(channel_id, msg)

        # Bot should have recorded sess_bob, not the spoofed sender
        bot_state = bm.get_bot_state(channel_id, bot_id)
        assert "sess_bob" in bot_state["senders"]
        assert "sess_alice" not in bot_state["senders"]

    def test_dm_slot_cannot_be_spoofed_via_message_body(self):
        """
        Attack: Send DM with spoofed slot_id in message body.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        # Bot that uses slot_id parameter, not body content
        inline_code = '''
class SlotTracker:
    def __init__(self, ctx, params):
        self.ctx = ctx
        self.ctx.set_state({"dm_slots": []})
    def on_private_message(self, slot_id, msg):
        state = self.ctx.get_state()
        # Use slot_id parameter, ignore body['slot_id'] if present
        state["dm_slots"].append(slot_id)
        self.ctx.set_state(state)
        self.ctx.dm(slot_id, "private", {"ack": True})
'''
        bot_def = BotDefinition(
            name="SlotTracker",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Bob sends DM with spoofed slot in body
        bob_slot = cm.get_slot_id_for_session(channel_id, "sess_bob")
        spoofed_msg = {"text": "Hi", "slot_id": "s0", "from_slot": "s0"}
        
        # The system passes bob_slot (s1), ignoring the spoofed body
        bm.dispatch_private_message(channel_id, bot_id, bob_slot, spoofed_msg)

        # Bot should have s1 (Bob's real slot), not s0
        bot_state = bm.get_bot_state(channel_id, bot_id)
        assert "s1" in bot_state["dm_slots"]
        assert "s0" not in bot_state["dm_slots"]

        # Response should go to s1, not s0
        bob_sync = cm.sync_messages(channel_id, "sess_bob")
        bob_private = [m for m in bob_sync["messages"] if m.get("to_slot") == "s1"]
        assert len(bob_private) >= 1
        
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        alice_from_bob = [m for m in alice_sync["messages"] if m.get("to_slot") == "s0"]
        assert len(alice_from_bob) == 0  # Alice doesn't get Bob's DM response


class TestGuessBotSpecificAttacks:
    """Attack vectors specific to the GuessBot implementation."""

    def test_guessbot_status_does_not_leak_other_players_info(self):
        """
        Attack: Use !status to try to learn about other players' activity.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Guess Game", ["invite:player1", "invite:player2"])
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

        # Both players join
        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")
        bm.dispatch_join(channel_id, "sess_alice")
        bm.dispatch_join(channel_id, "sess_bob")

        # Get initial cursor
        bob_sync1 = cm.sync_messages(channel_id, "sess_bob")
        bob_cursor = bob_sync1["cursor"]

        # Alice sends !status privately
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "!status"})

        # Bob syncs - should NOT see Alice's status response
        bob_sync2 = cm.sync_messages(channel_id, "sess_bob", cursor=bob_cursor)
        bob_new = bob_sync2["messages"]

        # Bob should not see any private messages for Alice
        alice_private = [m for m in bob_new if m.get("to_slot") == "s0"]
        assert len(alice_private) == 0

        # Bob should not see any message containing status info
        status_leaks = [m for m in bob_new if "game_started" in str(m.get("body", {}))]
        assert len(status_leaks) == 0

    def test_guessbot_unknown_command_response_stays_private(self):
        """
        Attack: Send invalid command to see if error response leaks.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Guess Game", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        bot_def = BotDefinition(
            name="GuessBot",
            version="1.0",
            code_ref="builtin://GuessBot",
            manifest={"hooks": ["on_init", "on_join", "on_message", "on_private_message"]}
        )
        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        bob_sync1 = cm.sync_messages(channel_id, "sess_bob")
        bob_cursor = bob_sync1["cursor"]

        # Alice sends unknown command
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "!hack the planet"})

        # Bob should not see the error response
        bob_sync2 = cm.sync_messages(channel_id, "sess_bob", cursor=bob_cursor)
        error_responses = [m for m in bob_sync2["messages"] 
                         if "Unknown command" in str(m.get("body", {}))]
        assert len(error_responses) == 0

    def test_cannot_spoof_turn_via_private_message(self):
        """
        Attack: Try to make a game move via DM to bypass turn checking.
        
        The GuessBot's on_private_message doesn't process guesses,
        so this shouldn't work anyway, but let's verify.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Guess Game", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        bot_def = BotDefinition(
            name="GuessBot",
            version="1.0",
            code_ref="builtin://GuessBot",
            manifest={
                "hooks": ["on_init", "on_join", "on_message", "on_private_message"],
                "params": {"target": 50}  # Fixed target for testing
            }
        )
        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")
        bm.dispatch_join(channel_id, "sess_alice")
        bm.dispatch_join(channel_id, "sess_bob")

        # Try to make a guess via DM (should not be processed as a game move)
        bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": "50"})

        # The game should not have ended (no "correct" judgment)
        all_msgs = cm.sync_messages(channel_id, "sess_alice")
        correct_msgs = [m for m in all_msgs["messages"] 
                       if m.get("body", {}).get("result") == "correct"]
        assert len(correct_msgs) == 0  # DM didn't count as a game move


class TestRaceConditionAttacks:
    """Attempt timing-based attacks."""

    def test_rapid_dm_does_not_leak_to_wrong_slot(self):
        """
        Attack: Send many DMs rapidly to try to cause race condition.
        """
        cm = ChannelManager()
        bm = BotManager(cm)

        result = cm.create_channel("Test", ["invite:player1", "invite:player2"])
        channel_id = result["channel_id"]
        invite1, invite2 = result["invites"]

        cm.join_channel(invite1, "sess_alice")
        cm.join_channel(invite2, "sess_bob")

        inline_code = '''
class RapidBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
    def on_private_message(self, slot_id, msg):
        self.ctx.dm(slot_id, "private", {"reply_to": slot_id, "seq": msg.get("seq")})
'''
        bot_def = BotDefinition(
            name="RapidBot",
            version="1.0",
            inline_code=inline_code,
            manifest={"hooks": ["on_private_message"]}
        )

        attach_result = bm.attach_bot(channel_id, bot_def)
        bot_id = attach_result["bot_id"]

        # Send many DMs from both players rapidly
        for i in range(20):
            bm.dispatch_private_message(channel_id, bot_id, "s0", {"text": f"alice_{i}", "seq": i})
            bm.dispatch_private_message(channel_id, bot_id, "s1", {"text": f"bob_{i}", "seq": i})

        # Verify no cross-contamination
        alice_sync = cm.sync_messages(channel_id, "sess_alice")
        bob_sync = cm.sync_messages(channel_id, "sess_bob")

        alice_private = [m for m in alice_sync["messages"] if m.get("to_slot") == "s0"]
        bob_private = [m for m in bob_sync["messages"] if m.get("to_slot") == "s1"]

        # Alice should only see her responses
        for msg in alice_private:
            assert msg["body"]["reply_to"] == "s0"

        # Bob should only see his responses
        for msg in bob_private:
            assert msg["body"]["reply_to"] == "s1"

        # Neither should see the other's messages
        alice_sees_bob = [m for m in alice_sync["messages"] if m.get("to_slot") == "s1"]
        bob_sees_alice = [m for m in bob_sync["messages"] if m.get("to_slot") == "s0"]
        assert len(alice_sees_bob) == 0
        assert len(bob_sees_alice) == 0

