#!/usr/bin/env python3
"""
Bot Manager - Bot attachment and execution for MCP Multiplayer
"""

import hashlib
import json
import threading
import importlib.util
import tempfile
import os
import signal
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Type
from pathlib import Path
from RestrictedPython import compile_restricted, safe_builtins, limited_builtins, safe_globals
from RestrictedPython.Guards import guarded_iter_unpack_sequence, safer_getattr

@dataclass
class BotManifest:
    name: str
    version: str
    hooks: List[str]
    emits: List[str]
    summary: str
    params: Dict[str, Any]

@dataclass
class BotDefinition:
    name: str
    version: str
    inline_code: Optional[str] = None
    code_ref: Optional[str] = None
    manifest: Optional[Dict[str, Any]] = None
    env_redacted: Optional[Dict[str, str]] = None

class BotContext:
    """Context provided to bots for posting messages and accessing state."""

    def __init__(self, channel_id: str, bot_id: str, bot_manager: 'BotManager'):
        self.channel_id = channel_id
        self.bot_id = bot_id
        self.bot_manager = bot_manager
        self.env = {}
        # Bot-specific tmpfs workspace
        self.workspace = f"/tmp/bot_workspace/{channel_id}_{bot_id}"
        os.makedirs(self.workspace, exist_ok=True)

    def post(self, kind: str, body: Dict[str, Any]):
        """Post a message to the channel."""
        return self.bot_manager.post_message_from_bot(
            self.channel_id, self.bot_id, kind, body
        )

    def get_state(self) -> Dict[str, Any]:
        """Get bot's current state."""
        return self.bot_manager.get_bot_state(self.channel_id, self.bot_id)

    def set_state(self, state: Dict[str, Any]):
        """Update bot's state."""
        return self.bot_manager.set_bot_state(self.channel_id, self.bot_id, state)

    def dm(self, slot_id: str, kind: str, body: Dict[str, Any]):
        """Send a private message to a specific player slot."""
        return self.bot_manager.post_private_message_from_bot(
            self.channel_id, self.bot_id, slot_id, kind, body
        )

class BotInstance:
    """Runtime instance of a bot attached to a channel."""

    def __init__(self, bot_id: str, bot_def: BotDefinition, bot_class: Type):
        self.bot_id = bot_id
        self.bot_def = bot_def
        self.bot_class = bot_class
        self.state = {}
        self.state_version = 0
        self.created_at = datetime.utcnow().isoformat()

    def create_bot_object(self, ctx: BotContext) -> Any:
        """Create a new instance of the bot."""
        params = self.bot_def.manifest.get("params", {}) if self.bot_def.manifest else {}
        return self.bot_class(ctx, params)

class BotManager:
    """Manages bot attachment, execution, and state."""

    def __init__(self, channel_manager):
        self.channel_manager = channel_manager
        self.bot_instances: Dict[str, Dict[str, BotInstance]] = {}  # channel_id -> bot_id -> instance
        self.bot_classes: Dict[str, Type] = {}  # name -> class
        self.lock = threading.RLock()

        # Load built-in bots
        self._load_builtin_bots()

    def _load_builtin_bots(self):
        """Load bots from the bots/ directory."""
        bots_dir = Path("bots")
        if not bots_dir.exists():
            return

        for bot_file in bots_dir.glob("*.py"):
            if bot_file.name.startswith("__"):
                continue

            try:
                spec = importlib.util.spec_from_file_location(
                    bot_file.stem, bot_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Look for bot classes (conventionally capitalized)
                for attr_name in dir(module):
                    if attr_name[0].isupper() and not attr_name.startswith("_"):
                        bot_class = getattr(module, attr_name)
                        if hasattr(bot_class, "__init__") and callable(bot_class):
                            self.bot_classes[attr_name] = bot_class

            except Exception as e:
                print(f"Failed to load bot from {bot_file}: {e}")

    def attach_bot(self, channel_id: str, bot_def: BotDefinition) -> Dict[str, Any]:
        """
        Attach a bot to a channel.

        Returns:
            {bot_id, code_hash, manifest_hash}
        """
        with self.lock:
            # Validate channel exists
            if channel_id not in self.channel_manager.channels:
                raise ValueError("CHANNEL_NOT_FOUND")

            # Generate bot ID
            bot_id = f"bot_{bot_def.name}_{len(self.bot_instances.get(channel_id, {}))}"

            # Load bot code
            bot_class = self._load_bot_code(bot_def)

            # Create bot instance
            bot_instance = BotInstance(bot_id, bot_def, bot_class)

            # Store instance
            if channel_id not in self.bot_instances:
                self.bot_instances[channel_id] = {}
            self.bot_instances[channel_id][bot_id] = bot_instance

            # Register bot in channel by finding a bot slot or creating one
            channel = self.channel_manager.channels[channel_id]
            bot_slot = next((slot for slot in channel["slots"]
                           if slot.kind == "bot" and slot.filled_by is None), None)

            if bot_slot:
                bot_slot.filled_by = f"bot:{bot_def.name}"
            else:
                # Add a new bot slot if none available
                from channel_manager import Slot
                new_slot = Slot(
                    slot_id=f"s{len(channel['slots'])}",
                    kind="bot",
                    label=f"bot:{bot_def.name}",
                    filled_by=f"bot:{bot_def.name}",
                    admin=True
                )
                channel["slots"].append(new_slot)

            # Generate hashes
            code_hash = self._compute_code_hash(bot_def)
            manifest_hash = self._compute_manifest_hash(bot_def.manifest or {})

            # Post control message about bot attachment
            self.channel_manager._post_system_message(channel_id, {
                "type": "bot:attach",
                "bot_id": bot_id,
                "code_hash": code_hash,
                "manifest_hash": manifest_hash,
                "name": bot_def.name
            })

            # Post manifest excerpt
            if bot_def.manifest:
                self.channel_manager._post_system_message(channel_id, {
                    "type": "bot:manifest",
                    "bot_id": bot_id,
                    "manifest_excerpt": {
                        "name": bot_def.name,
                        "version": bot_def.version,
                        "summary": bot_def.manifest.get("summary", ""),
                        "hooks": bot_def.manifest.get("hooks", []),
                        "emits": bot_def.manifest.get("emits", [])
                    }
                })

            # Initialize bot
            self._call_bot_hook(channel_id, bot_id, "on_init")

            return {
                "bot_id": bot_id,
                "code_hash": code_hash,
                "manifest_hash": manifest_hash
            }

    def _load_bot_code(self, bot_def: BotDefinition) -> Type:
        """Load bot code from definition."""
        if bot_def.code_ref:
            # Handle code_ref (e.g., "tool://dynamic_toolbox/GuessBot")
            if bot_def.code_ref.startswith("builtin://"):
                bot_name = bot_def.code_ref.split("/")[-1]
                if bot_name in self.bot_classes:
                    return self.bot_classes[bot_name]
                else:
                    raise ValueError(f"Unknown builtin bot: {bot_name}")
            else:
                raise ValueError(f"Unsupported code_ref: {bot_def.code_ref}")

        elif bot_def.inline_code:
            # Execute inline code and extract bot class
            return self._compile_inline_code(bot_def.inline_code, bot_def.name)

        else:
            raise ValueError("Bot definition must have either code_ref or inline_code")

    def _compile_inline_code(self, code: str, bot_name: str) -> Type:
        """Compile inline code with RestrictedPython and extract bot class."""
        # Compile with RestrictedPython
        byte_code = compile_restricted(
            code,
            filename=f'<bot:{bot_name}>',
            mode='exec'
        )

        if hasattr(byte_code, 'errors') and byte_code.errors:
            raise ValueError(f"Compilation errors: {byte_code.errors}")

        # Create restricted globals with safe imports
        restricted_globals = {
            '__builtins__': self._create_safe_builtins(),
            '_getiter_': guarded_iter_unpack_sequence,
            '_iter_unpack_sequence_': guarded_iter_unpack_sequence,
            '_getattr_': safer_getattr,
            '_getitem_': lambda obj, index: obj[index],
            '_print_': lambda x: print(x),
            '_write_': lambda x: x,
            '_inplacevar_': lambda op, x, y: op(x, y),
            '__name__': f'bot_{bot_name}',
            '__metaclass__': type,
        }

        # Execute in restricted environment
        code_obj = byte_code if isinstance(byte_code, type(compile('', '', 'exec'))) else byte_code.code
        exec(code_obj, restricted_globals)

        # Look for the bot class
        bot_class = None
        if bot_name in restricted_globals:
            bot_class = restricted_globals[bot_name]
        else:
            for name, obj in restricted_globals.items():
                if (hasattr(obj, "__init__") and callable(obj) and
                    not name.startswith("_") and name[0].isupper()):
                    bot_class = obj
                    break

        if not bot_class:
            raise ValueError(f"No bot class found in inline code for {bot_name}")

        return bot_class

    def _create_safe_builtins(self):
        """Create safe builtins for bot execution."""
        safe = safe_builtins.copy()
        safe.update(limited_builtins)

        # Add commonly needed builtins that are safe
        safe['hasattr'] = hasattr
        safe['isinstance'] = isinstance
        safe['issubclass'] = issubclass
        safe['type'] = type
        safe['dict'] = dict
        safe['list'] = list
        safe['tuple'] = tuple
        safe['set'] = set
        safe['str'] = str
        safe['int'] = int
        safe['float'] = float
        safe['bool'] = bool

        # Allow safe imports for network/TLS bots
        def _safe_import(name, *args, **kwargs):
            allowed_modules = {
                # Core Python
                'json', 'math', 'random', 'datetime', 'time',
                're', 'base64', 'hashlib', 'hmac', 'secrets',
                'collections', 'itertools', 'functools',
                'io', 'traceback', 'sys', 'typing',
                # Network
                'socket', 'ssl', 'http', 'urllib', 'urllib3', 'requests',
                # Requests dependencies
                'certifi', 'charset_normalizer', 'idna',
                # Other utilities
                'email', 'warnings', 'weakref', 'copy'
            }

            base_module = name.split('.')[0]
            if base_module not in allowed_modules:
                raise ImportError(f"Import of '{name}' is not allowed")

            return __import__(name, *args, **kwargs)

        safe['__import__'] = _safe_import
        safe['__builtins__'] = safe

        return safe

    def compute_code_hash(self, bot_def: BotDefinition) -> str:
        """Compute SHA256 hash of bot code."""
        if bot_def.inline_code:
            content = bot_def.inline_code
        else:
            content = bot_def.code_ref or ""

        return "sha256:" + hashlib.sha256(content.encode()).hexdigest()

    def compute_manifest_hash(self, manifest: Dict[str, Any]) -> str:
        """Compute SHA256 hash of manifest."""
        manifest_json = json.dumps(manifest, sort_keys=True)
        return "sha256:" + hashlib.sha256(manifest_json.encode()).hexdigest()

    # Keep private aliases for backwards compatibility
    def _compute_code_hash(self, bot_def: BotDefinition) -> str:
        return self.compute_code_hash(bot_def)

    def _compute_manifest_hash(self, manifest: Dict[str, Any]) -> str:
        return self.compute_manifest_hash(manifest)

    def dispatch_message(self, channel_id: str, message: Dict[str, Any]):
        """Dispatch a message to all bots in the channel."""
        with self.lock:
            if channel_id not in self.bot_instances:
                return

            for bot_id, bot_instance in self.bot_instances[channel_id].items():
                try:
                    self._call_bot_hook(channel_id, bot_id, "on_message", message)
                except Exception as e:
                    print(f"Error dispatching message to bot {bot_id}: {e}")

    def dispatch_join(self, channel_id: str, session_id: str):
        """Dispatch join event to all bots in the channel."""
        with self.lock:
            if channel_id not in self.bot_instances:
                return

            for bot_id, bot_instance in self.bot_instances[channel_id].items():
                try:
                    self._call_bot_hook(channel_id, bot_id, "on_join", session_id)
                except Exception as e:
                    print(f"Error dispatching join to bot {bot_id}: {e}")

    def _call_bot_hook(self, channel_id: str, bot_id: str, hook_name: str, *args):
        """Call a specific hook on a bot with timeout."""
        if channel_id not in self.bot_instances:
            return

        bot_instance = self.bot_instances[channel_id].get(bot_id)
        if not bot_instance:
            return

        # Create bot context
        ctx = BotContext(channel_id, bot_id, self)

        # Create bot object
        bot_obj = bot_instance.create_bot_object(ctx)

        # Call hook if it exists
        if hasattr(bot_obj, hook_name):
            hook_method = getattr(bot_obj, hook_name)
            if callable(hook_method):
                try:
                    # Set timeout for bot execution (5 seconds)
                    def timeout_handler(signum, frame):
                        raise TimeoutError(f"Bot hook {hook_name} exceeded 5 second timeout")

                    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(5)

                    try:
                        hook_method(*args)
                    finally:
                        signal.alarm(0)
                        signal.signal(signal.SIGALRM, old_handler)

                except TimeoutError as e:
                    print(f"Timeout in bot {bot_id} hook {hook_name}: {e}")
                except Exception as e:
                    print(f"Error in bot {bot_id} hook {hook_name}: {e}")

    def post_message_from_bot(self, channel_id: str, bot_id: str, kind: str, body: Dict[str, Any]) -> Dict:
        """Post a message from a bot."""
        # Add bot metadata to body
        enhanced_body = {
            **body,
            "bot_id": bot_id,
            "state_version": self.get_bot_state_version(channel_id, bot_id)
        }

        # Use the bot's actual identifier for posting
        bot_sender = f"bot:{bot_id}"
        return self.channel_manager.post_message(
            channel_id, bot_sender, kind, enhanced_body
        )

    def post_private_message_from_bot(self, channel_id: str, bot_id: str,
                                       to_slot: str, kind: str, body: Dict[str, Any]) -> Dict:
        """Post a private message from a bot to a specific slot."""
        enhanced_body = {
            **body,
            "bot_id": bot_id,
            "state_version": self.get_bot_state_version(channel_id, bot_id)
        }
        bot_sender = f"bot:{bot_id}"
        return self.channel_manager.post_private_message(
            channel_id, bot_sender, to_slot, kind, enhanced_body
        )

    def dispatch_private_message(self, channel_id: str, target_bot_id: str,
                                  slot_id: str, message: Dict[str, Any]):
        """Dispatch a private message to a specific bot only (not broadcast)."""
        with self.lock:
            if channel_id not in self.bot_instances:
                return
            if target_bot_id not in self.bot_instances[channel_id]:
                return
            try:
                self._call_bot_hook(channel_id, target_bot_id, "on_private_message", slot_id, message)
            except Exception as e:
                print(f"Error dispatching private message to bot {target_bot_id}: {e}")

    def get_bot_state(self, channel_id: str, bot_id: str) -> Dict[str, Any]:
        """Get bot's state."""
        with self.lock:
            if channel_id in self.bot_instances and bot_id in self.bot_instances[channel_id]:
                return self.bot_instances[channel_id][bot_id].state.copy()
            return {}

    def set_bot_state(self, channel_id: str, bot_id: str, state: Dict[str, Any]):
        """Set bot's state."""
        with self.lock:
            if channel_id in self.bot_instances and bot_id in self.bot_instances[channel_id]:
                bot_instance = self.bot_instances[channel_id][bot_id]
                bot_instance.state = state.copy()
                bot_instance.state_version += 1

    def get_bot_state_version(self, channel_id: str, bot_id: str) -> int:
        """Get bot's state version."""
        with self.lock:
            if channel_id in self.bot_instances and bot_id in self.bot_instances[channel_id]:
                return self.bot_instances[channel_id][bot_id].state_version
            return 0

    def get_channel_bots(self, channel_id: str) -> List[Dict[str, Any]]:
        """Get all bots attached to a channel."""
        with self.lock:
            if channel_id not in self.bot_instances:
                return []

            bots = []
            for bot_id, bot_instance in self.bot_instances[channel_id].items():
                bots.append({
                    "bot_id": bot_id,
                    "name": bot_instance.bot_def.name,
                    "version": bot_instance.bot_def.version,
                    "manifest": bot_instance.bot_def.manifest,
                    "created_at": bot_instance.created_at,
                    "state_version": bot_instance.state_version
                })
            return bots