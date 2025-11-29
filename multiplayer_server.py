#!/usr/bin/env python3
"""
MCP Multiplayer Server - FastMCP server providing multiplayer channel tools
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dotenv import load_dotenv

from fastmcp import FastMCP
from fastmcp.server.context import request_ctx
from channel_manager import ChannelManager
from bot_manager import BotManager, BotDefinition

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global managers
channel_manager = ChannelManager()
bot_manager = BotManager(channel_manager)

# Create FastMCP instance
mcp = FastMCP("Multiplayer Channels")

def get_session_id():
    """Get session ID from FastMCP context (client-provided)."""
    try:
        ctx = request_ctx.get()
        if hasattr(ctx, 'request') and ctx.request:
            # Use the session ID that Claude provides
            session_id = ctx.request.headers.get('Mcp-Session-Id')
            if session_id:
                return session_id
    except:
        pass

    # Fallback to None - let FastMCP handle session management
    return None

@mcp.tool()
def health_check() -> str:
    """Check if the multiplayer server is healthy."""
    return f"Multiplayer server healthy at {datetime.utcnow().isoformat()}"

@mcp.tool()
def create_channel(
    name: str,
    slots: List[str],
    bot_code: Optional[str] = None,
    bot_preset: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a new multiplayer channel with specified slots.

    Args:
        name: Channel name
        slots: List of slot types like ["bot:guess-referee", "invite:player1", "invite:player2"]
        bot_code: Optional Python code for inline bot (runs in RestrictedPython sandbox). Must define a class with:
            - __init__(self, ctx, params): Initialize with context
            - on_init(): Called when bot attaches
            - on_join(player_id): Called when player joins
            - on_message(msg): Called on new messages
            - self.ctx.post(kind, body): Post messages to channel
            - self.ctx.get_state() / set_state(dict): Persist state (bots recreated each message)
            - self.ctx.workspace: tmpfs directory for bot temp files
            Allowed imports: json, random, requests, socket, ssl, hashlib, datetime, etc.
            Blocked: os, subprocess, eval, exec, underscore-prefixed names
        bot_preset: Optional preset bot name like "GuessBot" or "BlackjackBot" (ignored if bot_code provided)

    Example with preset:
        create_channel(
            name="Guessing Game",
            slots=["bot:referee", "invite:alice", "invite:bob"],
            bot_preset="GuessBot"
        )

    Example with inline code:
        create_channel(
            name="Echo Game",
            slots=["bot:echo", "invite:player"],
            bot_code='''class EchoBot:
    def __init__(self, ctx, params):
        self.ctx = ctx
    def on_init(self):
        self.ctx.post('system', {'text': 'Echo ready'})
    def on_message(self, msg):
        if msg.get('kind') == 'user':
            self.ctx.post('echo', {'text': msg['body']['text']})'''
        )

    Returns:
        Channel creation result with channel_id and invite codes.
        IMPORTANT: Use join_channel with an invite code to join - you'll receive a rejoin_token.
        Save the rejoin_token to rejoin if you disconnect or refresh your session.
    """
    try:
        if not name or not slots:
            raise ValueError("name and slots required")

        # Build bots list from simple parameters
        bots = []
        if bot_code:
            bots.append({
                "name": "CustomBot",
                "version": "1.0",
                "inline_code": bot_code,
                "manifest": {
                    "summary": "Custom inline bot",
                    "hooks": ["on_init", "on_join", "on_message"],
                    "emits": ["system"],
                    "params": {}
                }
            })
        elif bot_preset:
            # Preset mappings
            presets = {
                "GuessBot": {
                    "name": "GuessBot",
                    "version": "1.0",
                    "code_ref": "builtin://GuessBot",
                    "manifest": {
                        "summary": "Number guessing referee",
                        "hooks": ["on_init", "on_join", "on_message"],
                        "emits": ["prompt", "state", "turn", "judge"],
                        "params": {"mode": "number", "range": [1, 100]}
                    }
                },
                "BlackjackBot": {
                    "name": "BlackjackBot",
                    "version": "1.0",
                    "code_ref": "builtin://BlackjackBot",
                    "manifest": {
                        "summary": "Blackjack dealer and referee",
                        "hooks": ["on_init", "on_join", "on_message"],
                        "emits": ["bot"],
                        "params": {}
                    }
                }
            }
            if bot_preset in presets:
                bots.append(presets[bot_preset])
            else:
                raise ValueError(f"Unknown bot preset: {bot_preset}")

        # Create channel
        result = channel_manager.create_channel(name, slots, bots)

        # Attach bots if provided
        bot_errors = []
        for bot_spec in bots:
            try:
                bot_def = BotDefinition(
                    name=bot_spec["name"],
                    version=bot_spec.get("version", "1.0"),
                    code_ref=bot_spec.get("code_ref"),
                    inline_code=bot_spec.get("inline_code"),
                    manifest=bot_spec.get("manifest"),
                    env_redacted=bot_spec.get("env_redacted")
                )
                bot_manager.attach_bot(result["channel_id"], bot_def)
            except Exception as e:
                error_msg = f"Failed to attach bot {bot_spec.get('name')}: {e}"
                logger.error(error_msg)
                bot_errors.append(error_msg)

        if bot_errors:
            result["bot_errors"] = bot_errors

        return result

    except ValueError as e:
        raise ValueError(f"INVALID_REQUEST: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating channel: {e}")
        raise ValueError(f"INTERNAL_ERROR: Failed to create channel")

@mcp.tool()
def join_channel(invite_code: str) -> Dict[str, Any]:
    """
    Join or rejoin a multiplayer channel using an invite code or rejoin token.

    Args:
        invite_code: The invite code (e.g., "inv_...") or rejoin token (e.g., "rejoin_...")

    Returns:
        Join result with channel_id, slot_id, rejoin_token (save this!), view, and bots array.
        The bots array contains bot_id, name, manifest for each bot.
        Use bot_id with get_bot_code(channel_id, bot_id) to retrieve and verify bot code.
        The rejoin_token can be used to rejoin if you disconnect or refresh.
    """
    try:
        if not invite_code:
            raise ValueError("invite_code required")

        session_id = get_session_id()
        if not session_id:
            raise ValueError("NO_SESSION: Missing session ID from client")

        result = channel_manager.join_channel(invite_code, session_id)

        # Notify bots of the join
        bot_manager.dispatch_join(result["channel_id"], session_id)

        # Add bots info for easy access to bot_id
        bots = bot_manager.get_channel_bots(result["channel_id"])
        result["bots"] = bots

        return result

    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Error joining channel: {e}")
        raise ValueError(f"INTERNAL_ERROR: Failed to join channel")

@mcp.tool()
def post_message(channel_id: str, body: str = "", kind: str = "user") -> Dict[str, Any]:
    """
    Post a message to a multiplayer channel.

    Args:
        channel_id: The channel ID (e.g., "chn_...")
        body: Message text content
        kind: Message type, defaults to "user"

    Returns:
        Message posting result with message ID and timestamp
    """
    try:
        if not channel_id:
            raise ValueError("channel_id required")

        if body:
            body_dict = {"text": body}
        else:
            body_dict = {}

        session_id = get_session_id()
        if not session_id:
            raise ValueError("NO_SESSION: Missing session ID from client")

        result = channel_manager.post_message(channel_id, session_id, kind, body_dict)

        # Dispatch message to bots
        message = {
            "id": result["msg_id"],
            "channel_id": channel_id,
            "sender": session_id,
            "kind": kind,
            "body": body_dict,
            "ts": result["ts"]
        }
        bot_manager.dispatch_message(channel_id, message)

        return result

    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Error posting message: {e}")
        raise ValueError(f"INTERNAL_ERROR: Failed to post message")

@mcp.tool()
def sync_messages(channel_id: str, cursor: Optional[int] = None, timeout_ms: int = 25000) -> Dict[str, Any]:
    """
    Get messages from a channel since cursor.

    Cursor is your watermark - the highest message ID you've seen so far (default: 0).
    Returns all messages with ID > cursor, and new cursor to use for next call.
    The cursor only advances when new messages are returned.

    Args:
        channel_id: The channel ID
        cursor: Your watermark - highest message ID you've seen (default: 0). Pass None on first call.
        timeout_ms: Long-poll timeout in milliseconds

    Returns:
        Dict with 'messages' array, 'cursor' (int watermark for next call), and optional 'view'
    """
    try:
        if not channel_id:
            raise ValueError("channel_id required")

        session_id = get_session_id()
        if not session_id:
            raise ValueError("NO_SESSION: Missing session ID from client")

        result = channel_manager.sync_messages(
            channel_id, session_id, cursor, timeout_ms
        )

        return result

    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Error syncing messages: {e}")
        raise ValueError(f"INTERNAL_ERROR: Failed to sync messages")

@mcp.tool()
def get_channel_info(channel_id: str) -> Dict[str, Any]:
    """
    Get current channel information and member list.

    Args:
        channel_id: The channel ID

    Returns:
        Channel view with members and bots
    """
    try:
        if not channel_id:
            raise ValueError("channel_id required")

        session_id = get_session_id()
        if not session_id:
            raise ValueError("NO_SESSION: Missing session ID from client")

        # Check membership
        channel_manager._check_membership(channel_id, session_id)

        view = channel_manager._get_channel_view(channel_id)
        bots = bot_manager.get_channel_bots(channel_id)

        result = {
            "view": view.__dict__,
            "bots": bots
        }

        return result

    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Error getting channel info: {e}")
        raise ValueError(f"INTERNAL_ERROR: Failed to get channel info")

@mcp.tool()
def get_bot_code(channel_id: str, bot_id: str) -> Dict[str, Any]:
    """
    Retrieve bot code and manifest for verification and common knowledge.

    This enables clients to verify the code_hash posted in bot:attach messages,
    establishing trust through transparency.

    Args:
        channel_id: The channel ID
        bot_id: The bot ID (from bot:attach message)

    Returns:
        Bot code, manifest, and hashes for verification
    """
    try:
        session_id = get_session_id()
        if not session_id:
            raise ValueError("NO_SESSION: Missing session ID from client")

        # Verify channel membership
        channel_manager._check_membership(channel_id, session_id)

        # Get bot instance
        if channel_id not in bot_manager.bot_instances:
            raise ValueError("CHANNEL_NOT_FOUND")

        if bot_id not in bot_manager.bot_instances[channel_id]:
            raise ValueError("BOT_NOT_FOUND")

        bot_instance = bot_manager.bot_instances[channel_id][bot_id]
        bot_def = bot_instance.bot_def

        # Compute hashes for verification
        code_hash = bot_manager.compute_code_hash(bot_def)
        manifest_hash = bot_manager.compute_manifest_hash(bot_def.manifest or {})

        return {
            "bot_id": bot_id,
            "name": bot_def.name,
            "version": bot_def.version,
            "code_ref": bot_def.code_ref,
            "inline_code": bot_def.inline_code,
            "manifest": bot_def.manifest,
            "code_hash": code_hash,
            "manifest_hash": manifest_hash
        }

    except ValueError as e:
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"Error getting bot code: {e}", exc_info=True)
        raise ValueError(f"INTERNAL_ERROR: Failed to get bot code: {e}")

@mcp.tool()
def list_channels() -> Dict[str, Any]:
    """
    List all available channels (debug endpoint).

    Returns:
        List of all channels with basic info
    """
    channels = []
    for channel_id, channel in channel_manager.channels.items():
        channels.append({
            "channel_id": channel_id,
            "name": channel["name"],
            "slots": [slot.__dict__ for slot in channel["slots"]],
            "message_count": len(channel["messages"]),
            "bots": list(bot_manager.bot_instances.get(channel_id, {}).keys())
        })

    return {
        "channels": channels,
        "total_channels": len(channels)
    }

if __name__ == "__main__":
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "9201"))

    logger.info(f"Starting Multiplayer MCP server on {host}:{port}")
    mcp.run(transport="streamable-http", host=host, port=port)