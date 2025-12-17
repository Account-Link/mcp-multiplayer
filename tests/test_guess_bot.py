#!/usr/bin/env python3
"""
Tests for GuessBot
"""

import pytest
from unittest.mock import Mock, MagicMock
from bots.guess_bot import GuessBot

class MockContext:
    def __init__(self):
        self.channel_id = "test_channel"
        self.bot_id = "test_bot"
        self.bot_manager = Mock()
        self.bot_manager.get_bot_state_version.return_value = 1
        self.env = {}
        self._state = {}
        self.messages = []

    def post(self, kind, body):
        self.messages.append({"kind": kind, "body": body})
        return {"msg_id": len(self.messages), "ts": "2025-01-01T00:00:00Z"}

    def get_state(self):
        return self._state.copy()

    def set_state(self, state):
        self._state = state.copy()

class TestGuessBot:
    def test_initialization(self):
        ctx = MockContext()
        params = {"mode": "number", "range": [1, 100], "target": 42}

        bot = GuessBot(ctx, params)

        assert bot.mode == "number"
        assert bot.range == [1, 100]
        assert bot.target == 42
        assert bot.players == []
        assert bot.game_started is False
        assert bot.game_ended is False

    def test_on_init_posts_messages(self):
        ctx = MockContext()
        params = {"mode": "number", "range": [1, 50], "target": 25}

        bot = GuessBot(ctx, params)
        bot.on_init()

        # Check messages posted
        messages = ctx.messages
        assert len(messages) >= 2

        # Should have prompt and commitment
        prompt_msg = next((m for m in messages if m["body"].get("type") == "prompt"), None)
        assert prompt_msg is not None
        assert "Guess the number between 1 and 50" in prompt_msg["body"]["text"]

        commit_msg = next((m for m in messages if m["body"].get("type") == "bot:commit"), None)
        assert commit_msg is not None
        assert "commit" in commit_msg["body"]

    def test_player_joining(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_init()

        # First player joins
        bot.on_join("sess_123")
        assert "sess_123" in bot.players
        assert len(bot.players) == 1
        assert bot.game_started is False

        # Second player joins - should start game
        bot.on_join("sess_456")
        assert "sess_456" in bot.players
        assert len(bot.players) == 2
        assert bot.game_started is True

        # Check game start message
        start_msgs = [m for m in ctx.messages if m["body"].get("type") == "game_start"]
        assert len(start_msgs) == 1

        # Check turn message
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        assert len(turn_msgs) == 1

    def test_duplicate_player_join(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        initial_count = len(bot.players)

        # Same player joins again
        bot.on_join("sess_123")
        assert len(bot.players) == initial_count  # Should not increase

    def test_correct_guess(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        assert len(turn_msgs) >= 1
        first_player = turn_msgs[-1]["body"]["player"]

        # Player makes correct guess
        move_msg = {
            "kind": "user",
            "sender": first_player,  # Use the actual first player
            "body": {"text": 42}
        }

        bot.on_message(move_msg)

        # Check judge message
        judge_msgs = [m for m in ctx.messages if m["body"].get("type") == "judge"]
        assert len(judge_msgs) == 1
        assert judge_msgs[0]["body"]["result"] == "correct"

        # Check game ended
        assert bot.game_ended is True

        # Check reveal message
        reveal_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:reveal"]
        assert len(reveal_msgs) == 1
        assert reveal_msgs[0]["body"]["target"] == 42
        assert reveal_msgs[0]["body"]["verified"] is True

    def test_wrong_guess_high(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        first_player = turn_msgs[-1]["body"]["player"]

        # Player guesses too high
        move_msg = {
            "kind": "user",
            "sender": first_player,
            "body": {"text": "80"}
        }

        bot.on_message(move_msg)

        # Check judge message
        judge_msgs = [m for m in ctx.messages if m["body"].get("type") == "judge"]
        assert len(judge_msgs) == 1
        assert judge_msgs[0]["body"]["result"] == "high"

        # Game should continue
        assert bot.game_ended is False

        # Should advance turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        assert len(turn_msgs) >= 2  # Initial turn + advanced turn

    def test_wrong_guess_low(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        first_player = turn_msgs[-1]["body"]["player"]

        # Player guesses too low
        move_msg = {
            "kind": "user",
            "sender": first_player,
            "body": {"text": "10"}
        }

        bot.on_message(move_msg)

        # Check judge message
        judge_msgs = [m for m in ctx.messages if m["body"].get("type") == "judge"]
        assert len(judge_msgs) == 1
        assert judge_msgs[0]["body"]["result"] == "low"

    def test_out_of_turn_guess(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn and use the other player
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        first_player = turn_msgs[-1]["body"]["player"]
        wrong_player = "sess_456" if first_player == "sess_123" else "sess_123"

        # Wrong player tries to guess
        move_msg = {
            "kind": "user",
            "sender": wrong_player,
            "body": {"text": "50"}
        }

        bot.on_message(move_msg)

        # Check violation message
        violation_msgs = [m for m in ctx.messages if m["body"].get("type") == "violation"]
        assert len(violation_msgs) == 1
        assert violation_msgs[0]["body"]["reason"] == "BAD_TURN"

    def test_invalid_guess_range(self):
        ctx = MockContext()
        params = {"target": 42, "range": [1, 100]}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        first_player = turn_msgs[-1]["body"]["player"]

        # Guess outside range
        move_msg = {
            "kind": "user",
            "sender": first_player,
            "body": {"text": "150"}
        }

        bot.on_message(move_msg)

        # Check violation message
        violation_msgs = [m for m in ctx.messages if m["body"].get("type") == "violation"]
        assert len(violation_msgs) == 1
        assert violation_msgs[0]["body"]["reason"] == "BAD_MOVE"

    def test_invalid_guess_format(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        first_player = turn_msgs[-1]["body"]["player"]

        # Non-numeric guess
        move_msg = {
            "kind": "user",
            "sender": first_player,
            "body": {"text": "not_a_number"}
        }

        bot.on_message(move_msg)

        # Check violation message
        violation_msgs = [m for m in ctx.messages if m["body"].get("type") == "violation"]
        assert len(violation_msgs) == 1
        assert violation_msgs[0]["body"]["reason"] == "BAD_MOVE"

    def test_concede_action(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)
        bot.on_join("sess_123")
        bot.on_join("sess_456")

        # Check who has the first turn
        turn_msgs = [m for m in ctx.messages if m["body"].get("type") == "bot:turn"]
        first_player = turn_msgs[-1]["body"]["player"]

        # Player concedes
        move_msg = {
            "kind": "user",
            "sender": first_player,
            "body": {"text": "concede"}
        }

        bot.on_message(move_msg)

        # Check concede message
        concede_msgs = [m for m in ctx.messages if m["body"].get("type") == "concede"]
        assert len(concede_msgs) == 1
        assert concede_msgs[0]["body"]["player"] == first_player

        # Player should be removed
        assert first_player not in bot.players
        assert len(bot.players) == 1

    def test_hint_generation(self):
        ctx = MockContext()
        params = {"target": 50}

        bot = GuessBot(ctx, params)

        # Test different distances
        assert "very close" in bot._generate_hint(52)  # distance = 2
        assert "close" in bot._generate_hint(58)       # distance = 8
        assert "getting warm" in bot._generate_hint(65) # distance = 15
        assert "cold" in bot._generate_hint(80)        # distance = 30

    def test_commitment_verification(self):
        ctx = MockContext()
        params = {"target": 42}

        bot = GuessBot(ctx, params)

        # Test valid commitment
        target = 42
        nonce = bot.nonce
        commit = bot.commit

        assert bot._verify_commitment(target, nonce, commit) is True

        # Test invalid commitment
        assert bot._verify_commitment(43, nonce, commit) is False
        assert bot._verify_commitment(target, "wrong_nonce", commit) is False

    def test_state_persistence(self):
        ctx = MockContext()
        params = {"target": 42}

        # Create bot and set some state
        bot1 = GuessBot(ctx, params)
        bot1.on_join("sess_123")
        bot1.on_join("sess_456")

        # Get the saved state
        saved_state = ctx.get_state()

        # Create new bot with same context (simulating reload)
        ctx2 = MockContext()
        ctx2._state = saved_state

        bot2 = GuessBot(ctx2, params)

        # State should be restored
        assert bot2.target == 42
        assert bot2.players == ["sess_123", "sess_456"]
        assert bot2.game_started is True
        assert bot2.game_ended is False