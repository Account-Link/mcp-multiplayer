#!/usr/bin/env python3
"""
PsiBot - Private Set Intersection Bot
"""

import hashlib
import os
import random
import re
from typing import Dict, Any, List

class PsiBot:
    """
    A bot for Private Set Intersection Verification games.
    """

    def __init__(self, ctx, params):
        self.ctx = ctx
        self.params = params

        # Game parameters
        self.range = params.get('range', [1, 100])
        self.timeout_s = params.get('timeout_s', 600)
        self.intersection_size = params.get('intersection_size', 3)
        self.set_size = params.get('set_size', 10)

        # Initialize state
        state = self.ctx.get_state()
        if not state:
            # Ensure at least intersection_size numbers in the intersection
            intersection = random.sample(range(self.range[0], self.range[1] + 1), self.intersection_size)
            
            # Create set1: include all intersection numbers, then fill to set_size
            remaining1 = [x for x in range(self.range[0], self.range[1] + 1) if x not in intersection]
            additional1 = random.sample(remaining1, self.set_size - len(intersection))
            set1 = sorted(intersection + additional1)
            
            # Create set2: include all intersection numbers, then fill to set_size
            remaining2 = [x for x in range(self.range[0], self.range[1] + 1) if x not in intersection]
            additional2 = random.sample(remaining2, self.set_size - len(intersection))
            set2 = sorted(intersection + additional2)
            
            # Target is the intersection (should be at least intersection_size numbers)
            target = set(set1) & set(set2)

            self.target = params.get('target', target)  # intersection of set 1 and 2
            self.set1 = params.get('set1', set1)
            self.set2 = params.get('set2', set2)

            self.players = []
            self.game_started = False
            self.game_ended = False
            self.guesses = dict()
            self.sets = dict()

            # Save initial state
            self._save_state()
        else:
            # Load existing state
            self._load_state(state)

    def _save_state(self):
        """Save current state."""
        state = {
            'set1': self.set1,
            'set2': self.set2,
            'sets': self.sets,
            'target': self.target,
            'players': self.players,
            'guesses': self.guesses,
            'game_started': self.game_started,
            'game_ended': self.game_ended,
            'range': self.range
        }
        self.ctx.set_state(state)

    def _load_state(self, state: Dict[str, Any]):
        """Load state from storage."""
        self.set1 = state.get('set1')
        self.set2 = state.get('set2')
        self.sets = state.get('sets', dict())
        self.target = state.get('target')
        self.players = state.get('players', [])
        self.game_started = state.get('game_started', False)
        self.game_ended = state.get('game_ended', False)
        self.guesses = state.get('guesses', dict())
        self.range = state.get('range', [1, 100])
    
    def _extract_numbers(self, text):
        # Find all numbers in the string
        if not text:
            return None
        numbers = re.findall(r'\d+', text)
        if numbers:
            return [int(n) for n in numbers]  # Get the last number (or numbers[0] for first)
        return None

    def on_init(self):
        """Initialize the game when bot is attached."""
        # Post game prompt
        self.ctx.post("bot", {
            "type": "prompt",
            "text": f"Private Set Intersection Verification game!\n Guess the intersection (with range {self.range[0]} and {self.range[1]}) between your set and your opponent's set!",
            "range": self.range
        })

        # Post initial state
        self._post_public_state()

    def on_join(self, slot_id: str):
        """Handle a player joining the channel."""
        if slot_id not in self.players and not self.game_ended:
            self.players.append(slot_id)
            
            self._save_state()

            self.ctx.post("bot", {
                "type": "player_joined",
                "player": slot_id,
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

        self.ctx.dm(slot_id, "private", {
            "type": "error",
            "text": f"Unknown command: {text}. Try !help"
        })

    def _start_game(self):
        """Start the game when enough players have joined."""
        self.game_started = True

        self._save_state()

        self.ctx.post("bot", {
            "type": "game_start",
            "players": self.players,
        })

        self.sets[self.players[0]] = self.set1

        msgId = self.ctx.dm("s1", "private", {
            "text": f"Your set: {self.set1}"
        })

        self.sets[self.players[1]] = self.set2
        msgId = self.ctx.dm("s2", "private", {
            "text": f"Your set: {self.set2}"
        })

    def _handle_guess_move(self, sender: str, body: Dict[str, Any]):
        """Handle a guess move from a player."""
        if not self.game_started:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "GAME_NOT_STARTED",
                "details": "Game hasn't started yet"
            })
            return

        if sender in self.guesses and self.guesses[sender] is not None:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "GUESS_ALREADY_MADE",
                "details": "You have already made a guess"
            })
            return

        # Get guess value
        guess_text = body.get('text', '')

        if not isinstance(guess_text, list):
            guess = self._extract_numbers(guess_text)
        else:
            guess = guess_text

        if guess is None:
            self.ctx.post("control", {
                "type": "violation",
                "reason": "BAD_MOVE",
                "details": "Missing guess value"
            })
            return

        # Check if intersection is correct
        self.guesses[sender] = guess
        result = "correct" if (set(guess) & set(self.target)) == set(self.target) else "incorrect"
        self.ctx.post("bot", {
            "type": "judge",
            "result": result,
            "player": sender,
            "guess": guess,
        })

        if len(self.guesses) == len(self.players):
            self._end_game()

        self._save_state()


    def _end_game(self, winner: str = None, reason: str = "correct"):
        """End the game and reveal the target."""
        self.game_ended = True
        self._save_state()


        self.ctx.post("control", {
            "type": "bot:reveal",
            "target": self.target,
        })

        # Announce game end
        self.ctx.post("bot", {
            "type": "game_end",
            "winner": winner,
            "reason": reason,
            "target": self.target,
            "players": self.players
        })

        self.ctx.post("system", {
            "type": "end"
        })

    def _post_public_state(self):
        """Post the current public game state."""
        public_state = {
            "range": self.range,
            "players": self.players,
            "game_started": self.game_started,
            "game_ended": self.game_ended,
        }

        self.ctx.post("control", {
            "type": "bot:state",
            "public_state": public_state,
            "state_version": self.ctx.bot_manager.get_bot_state_version(
                self.ctx.channel_id, self.ctx.bot_id
            )
        })