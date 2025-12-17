#!/usr/bin/env python3
"""
GuessBot - Turn-based number guessing referee bot
"""

import hashlib
import os
import random
import re
from typing import Dict, Any, List

class GuessBot:
    """
    A referee bot for turn-based number guessing games.

    Supports number mode with configurable ranges and commitment-reveal.
    """

    def __init__(self, ctx, params):
        self.ctx = ctx
        self.params = params

        # Game parameters
        self.mode = params.get('mode', 'number')
        self.range = params.get('range', [1, 100])
        self.timeout_s = params.get('timeout_s', 600)

        # Initialize state
        state = self.ctx.get_state()
        if not state:
            # First time initialization
            self.target = params.get('target') or random.randint(self.range[0], self.range[1])
            self.nonce = os.urandom(16).hex()
            self.commit = self._compute_commitment(self.target, self.nonce)
            self.players = []
            self.turn_index = 0
            self.game_started = False
            self.game_ended = False
            self.guess_count = 0

            # Save initial state
            self._save_state()
        else:
            # Load existing state
            self._load_state(state)

    def _compute_commitment(self, target: int, nonce: str) -> str:
        """Compute commitment hash for the target."""
        data = f"{target}|{nonce}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _verify_commitment(self, target: int, nonce: str, commit: str) -> bool:
        """Verify a commitment."""
        return self._compute_commitment(target, nonce) == commit

    def _save_state(self):
        """Save current state."""
        state = {
            'target': self.target,
            'nonce': self.nonce,
            'commit': self.commit,
            'players': self.players,
            'turn_index': self.turn_index,
            'game_started': self.game_started,
            'game_ended': self.game_ended,
            'guess_count': self.guess_count,
            'mode': self.mode,
            'range': self.range
        }
        self.ctx.set_state(state)

    def _load_state(self, state: Dict[str, Any]):
        """Load state from storage."""
        self.target = state.get('target')
        self.nonce = state.get('nonce')
        self.commit = state.get('commit')
        self.players = state.get('players', [])
        self.turn_index = state.get('turn_index', 0)
        self.game_started = state.get('game_started', False)
        self.game_ended = state.get('game_ended', False)
        self.guess_count = state.get('guess_count', 0)
        self.mode = state.get('mode', 'number')
        self.range = state.get('range', [1, 100])
    
    def _extract_number(self, text):
        # Find all numbers in the string
        if not text:
            return None
        numbers = re.findall(r'\d+', text)
        if numbers:
            return int(numbers[-1])  # Get the last number (or numbers[0] for first)
        return None

    def on_init(self):
        """Initialize the game when bot is attached."""
        # Post game prompt
        self.ctx.post("bot", {
            "type": "prompt",
            "text": f"Guess the number between {self.range[0]} and {self.range[1]}!",
            "mode": self.mode,
            "range": self.range
        })

        # Post commitment
        self.ctx.post("control", {
            "type": "bot:commit",
            "commit": self.commit,
            "message": "Target committed - game will reveal at end"
        })

        # Post initial state
        self._post_public_state()

    def on_join(self, session_id: str):
        """Handle a player joining the channel."""
        if session_id not in self.players and not self.game_ended:
            self.players.append(session_id)
            self._save_state()

            self.ctx.post("bot", {
                "type": "player_joined",
                "player": session_id,
                "player_count": len(self.players)
            })

            # Start game when we have 2 players
            if len(self.players) >= 2 and not self.game_started:
                self._start_game()

    def on_message(self, msg: Dict[str, Any]):
        """Handle incoming messages."""
        if msg.get('kind') != 'user':
            return

        if self.game_ended:
            return

        body = msg.get('body', {})
        sender = msg.get('sender')

        # Check if message text contains "guess" or process all user messages
        text = body.get('text', '')
        if text:
            self._handle_guess_move(sender, body)

    def on_private_message(self, slot_id: str, msg: Dict[str, Any]):
        """Handle private messages from players (via dm_bot)."""
        text = msg.get('text', '').strip()

        if text == '!status':
            # Respond with game status privately
            current_turn = None
            if self.players and not self.game_ended:
                current_turn = self.players[self.turn_index % len(self.players)]

            self.ctx.dm(slot_id, "private", {
                "type": "status",
                "game_started": self.game_started,
                "game_ended": self.game_ended,
                "player_count": len(self.players),
                "guess_count": self.guess_count,
                "current_turn": current_turn,
                "range": self.range
            })

        elif text == '!help':
            self.ctx.dm(slot_id, "private", {
                "type": "help",
                "commands": ["!status - Get game status", "!help - Show this help"],
                "note": "Use public messages for guesses"
            })

        else:
            self.ctx.dm(slot_id, "private", {
                "type": "error",
                "text": f"Unknown command: {text}. Try !help"
            })

    def _start_game(self):
        """Start the game when enough players have joined."""
        self.game_started = True

        # Randomize turn order if requested
        if self.params.get('turn_order') == 'random':
            random.shuffle(self.players)

        self._save_state()

        self.ctx.post("bot", {
            "type": "game_start",
            "players": self.players,
            "turn_order": self.players
        })

        # Start first turn
        self._advance_turn()

    def _handle_guess_move(self, sender: str, body: Dict[str, Any]):
        """Handle a guess move from a player."""
        if not self.game_started:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "GAME_NOT_STARTED",
                "details": "Game hasn't started yet"
            })
            return

        # Check if it's the player's turn
        if len(self.players) == 0:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "GAME_NOT_STARTED",
                "details": "No players in game"
            })
            return

        current_player = self.players[self.turn_index % len(self.players)]
        if sender != current_player:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "BAD_TURN",
                "details": f"Not your turn. Current player: {current_player}"
            })
            return

        # Get guess value
        guess_text = body.get('text', '')
        if guess_text == "concede":
            self._handle_concede(sender)
            return
        if not isinstance(guess_text, int):
            guess = self._extract_number(guess_text)
        else:
            guess = guess_text
        if guess is None:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "BAD_MOVE",
                "details": "Missing guess value"
            })
            return

        # Validate range
        if guess < self.range[0] or guess > self.range[1]:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "BAD_MOVE",
                "details": f"Guess must be between {self.range[0]} and {self.range[1]}"
            })
            return

        # Process the guess
        self._process_guess(sender, guess)

    def _process_guess(self, player: str, guess: int):
        """Process a valid guess."""
        self.guess_count += 1

        if guess == self.target:
            # Correct guess - game ends
            self.ctx.post("bot", {
                "type": "judge",
                "result": "correct",
                "player": player,
                "guess": guess,
                "guess_count": self.guess_count
            })

            self._end_game(player)
        else:
            # Wrong guess - give hint and continue
            result = "high" if guess > self.target else "low"
            hint = self._generate_hint(guess)

            self.ctx.post("bot", {
                "type": "judge",
                "result": result,
                "player": player,
                "guess": guess,
                "hint": hint,
                "guess_count": self.guess_count
            })

            # Advance to next turn
            self._advance_turn()

        self._save_state()

    def _generate_hint(self, guess: int) -> str:
        """Generate a helpful hint based on the guess."""
        distance = abs(guess - self.target)

        if distance <= 5:
            return "very close!"
        elif distance <= 10:
            return "close"
        elif distance <= 20:
            return "getting warm"
        else:
            return "cold"

    def _advance_turn(self):
        """Advance to the next player's turn."""
        if not self.players or self.game_ended:
            return

        self.turn_index = (self.turn_index + 1) % len(self.players)
        current_player = self.players[self.turn_index]

        self.ctx.post("control", {
            "type": "bot:turn",
            "player": current_player,
            "turn_number": self.guess_count + 1,
            "state_version": self.ctx.bot_manager.get_bot_state_version(
                self.ctx.channel_id, self.ctx.bot_id
            )
        })

    def _handle_concede(self, player: str):
        """Handle a player conceding."""
        self.ctx.post("bot", {
            "type": "concede",
            "player": player
        })

        # Remove player from game
        if player in self.players:
            self.players.remove(player)

        # If only one player left, they win
        if len(self.players) <= 1:
            winner = self.players[0] if self.players else None
            self._end_game(winner, reason="concede")
        else:
            # Continue with remaining players
            if self.turn_index >= len(self.players):
                self.turn_index = 0
            self._advance_turn()

        self._save_state()

    def _end_game(self, winner: str = None, reason: str = "correct"):
        """End the game and reveal the target."""
        self.game_ended = True
        self._save_state()

        # Verify commitment and reveal
        verified = self._verify_commitment(self.target, self.nonce, self.commit)

        self.ctx.post("control", {
            "type": "bot:reveal",
            "target": self.target,
            "nonce": self.nonce,
            "commit": self.commit,
            "verified": verified
        })

        # Announce game end
        self.ctx.post("bot", {
            "type": "game_end",
            "winner": winner,
            "reason": reason,
            "target": self.target,
            "total_guesses": self.guess_count,
            "players": self.players
        })

        self.ctx.post("system", {
            "type": "end"
        })

    def _post_public_state(self):
        """Post the current public game state."""
        public_state = {
            "mode": self.mode,
            "range": self.range,
            "players": self.players,
            "game_started": self.game_started,
            "game_ended": self.game_ended,
            "current_turn": self.players[self.turn_index] if self.players else None,
            "guess_count": self.guess_count
        }

        self.ctx.post("control", {
            "type": "bot:state",
            "public_state": public_state,
            "state_version": self.ctx.bot_manager.get_bot_state_version(
                self.ctx.channel_id, self.ctx.bot_id
            )
        })