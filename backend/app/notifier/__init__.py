"""Canaux de notification : SSE (navigateur), e-mail et Discord."""

from app.notifier import discord, email, stream

__all__ = ["stream", "email", "discord"]
