# Telegram Alert System Blueprint

## Overview
Real-time threat alerts via Telegram for Cowrie honeypot attacks.

## Components
1. Alert generation (severity-based)
2. Telegram bot integration
3. Rate limiting
4. Alert deduplication

## Implementation
- Module: src/alerter.py
- Config: telegram_token, telegram_chat_id
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW
