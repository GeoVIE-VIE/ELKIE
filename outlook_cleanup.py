#!/usr/bin/env python3
"""
Outlook Inbox Cleanup — One-time batch scan of existing emails.

Modes:
    --mode phishing    Score-based phishing/spam detection (default)
    --mode marketing   Detect and move bulk marketing/newsletter emails
    --mode both        Run both passes

Usage:
    python3 outlook_cleanup.py --dry-run --mode marketing    # preview marketing cleanup
    python3 outlook_cleanup.py --mode marketing              # move marketing to junk
    python3 outlook_cleanup.py --mode both --max-emails 5000 # full cleanup
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import msal
import requests

# --- Reuse scoring logic from outlook_sentinel.py ---

WHITELISTED_SENDER_DOMAINS = {
    "linkedin.com", "redditmail.com", "reddit.com", "facebookmail.com",
    "twitter.com", "x.com", "instagram.com", "discord.com",
    "microsoft.com", "accountprotection.microsoft.com", "google.com",
    "apple.com", "amazon.com", "github.com", "paypal.com",
    "netflix.com", "spotify.com", "adobe.com", "zoom.us",
    "webull.com", "hilton.com", "harborfreight.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
    "vanguard.com", "fidelity.com", "schwab.com",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com",
    "steam-chat.com", "steampowered.com", "epicgames.com",
    "twitch.tv", "youtube.com", "slack.com",
}

SPAM_SENDER_PATTERNS = [
    re.compile(r"@.*\.xyz$", re.I),
    re.compile(r"@.*\.top$", re.I),
    re.compile(r"@.*\.buzz$", re.I),
    re.compile(r"@.*\.club$", re.I),
    re.compile(r"@.*\.icu$", re.I),
    re.compile(r"@.*\.work$", re.I),
    re.compile(r"@.*\.click$", re.I),
    re.compile(r"@.*\.tk$", re.I),
    re.compile(r"@.*\.ml$", re.I),
    re.compile(r"@.*\.ga$", re.I),
    re.compile(r"@.*\.cf$", re.I),
]

PHISHING_SUBJECT_PATTERNS = [
    re.compile(r"(account|password|verify|suspend|unusual|unauthorized|security alert|action required)", re.I),
    re.compile(r"(confirm your|update your|validate your|unlock your)", re.I),
    re.compile(r"(you have won|congratulations|claim your|prize)", re.I),
    re.compile(r"(wire transfer|invoice|payment|receipt|statement)", re.I),
    re.compile(r"(urgent|immediate|within 24 hours|act now|limited time)", re.I),
]

PHISHING_BODY_PATTERNS = [
    re.compile(r"(click here|click below|click this link)", re.I),
    re.compile(r"(verify your identity|confirm your account|update your information)", re.I),
    re.compile(r"(social security|ssn|credit card|bank account|routing number)", re.I),
    re.compile(r"(bitcoin|cryptocurrency|crypto wallet|btc address)", re.I),
    re.compile(r"(dear customer|dear user|dear account holder|valued customer)", re.I),
    re.compile(r"(kindly|do the needful|revert back)", re.I),
]

SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"https?://[^/]*\.(xyz|top|buzz|club|icu|tk|ml|ga|cf|pw|work|click)/", re.I),
]

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
TRUSTED_DOMAINS = {
    "microsoft.com", "google.com", "apple.com", "amazon.com", "github.com",
    "paypal.com", "outlook.com", "live.com", "hotmail.com", "office.com",
    "linkedin.com", "facebook.com", "twitter.com", "youtube.com",
    "netflix.com", "spotify.com", "adobe.com", "zoom.us",
}

# Marketing/newsletter sender patterns — subdomain-based bulk senders
MARKETING_SENDER_PATTERNS = [
    re.compile(r"@[a-z]\.[a-z]+\.\w+$", re.I),       # @s.kohls.com, @b.express.com, @e.chase.com
    re.compile(r"@(e|em|email|mail|news|hello|info|marketing|promo|offers|deals)\.", re.I),
    re.compile(r"@(newsletter|updates|notifications|alerts|digest)\.", re.I),
    re.compile(r"@order\.", re.I),
    re.compile(r"noreply|no-reply|donotreply|do-not-reply", re.I),
]

# Senders you actually want to keep even if they look like marketing
KEEP_SENDERS = {
    "microsoft.com", "accountprotection.microsoft.com",
    "github.com", "google.com", "apple.com",
    "chase.com",  # bank notifications are important
    "bankofamerica.com", "wellsfargo.com", "citi.com",
    "vanguard.com", "fidelity.com", "schwab.com",
    "interactivebrokers.com",
    "amazon.com",  # order confirmations
    "navyfederal.org",  # bank — withdrawal notifications are important
    "aspendental.com",  # appointment reminders
    "govdelivery.com",  # government notifications
}

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def is_marketing(msg):
    """Detect if an email is bulk marketing/newsletter."""
    from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "") or ""
    subject = msg.get("subject", "") or ""
    sender_domain = from_addr.split("@")[1].lower() if "@" in from_addr else ""

    # Never flag keep-list senders
    if any(sender_domain.endswith(d) for d in KEEP_SENDERS):
        return False, ""

    # Check marketing sender patterns
    for pattern in MARKETING_SENDER_PATTERNS:
        if pattern.search(from_addr):
            return True, f"Marketing sender: {from_addr}"

    # Common marketing subject indicators
    marketing_subjects = [
        re.compile(r"\b(off|sale|deal|save|discount|coupon|promo|free shipping)\b", re.I),
        re.compile(r"\b(% off|clearance|limited time|exclusive|don't miss)\b", re.I),
        re.compile(r"\b(unsubscribe|opt.out|preferences|manage.*subscription)\b", re.I),
        re.compile(r"(🎉|🔥|💰|🎁|⭐|✨|👀|🤩|📈|💛|🛒)", re.I),  # emoji-heavy subjects
    ]
    hits = sum(1 for p in marketing_subjects if p.search(subject))
    if hits >= 2:
        return True, f"Marketing subject ({hits} indicators)"

    return False, ""


def get_token():
    cache = msal.SerializableTokenCache()
    with open("/home/legs/.outlook_token_cache.json") as f:
        cache.deserialize(f.read())
    app = msal.PublicClientApplication(
        "49d62aab-a482-4485-a5cb-9af0a33d250e",
        authority="https://login.microsoftonline.com/common",
        token_cache=cache,
    )
    accounts = app.get_accounts()
    if not accounts:
        print("No accounts in cache. Run outlook_auth.py first.")
        sys.exit(1)
    result = app.acquire_token_silent(["Mail.Read", "Mail.ReadWrite"], account=accounts[0])
    if result and "access_token" in result:
        if cache.has_state_changed:
            with open("/home/legs/.outlook_token_cache.json", "w") as f:
                f.write(cache.serialize())
        return result["access_token"]
    print("Token refresh failed. Run outlook_auth.py again.")
    sys.exit(1)


def score_email(msg):
    subject = msg.get("subject", "") or ""
    from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "") or ""
    from_name = msg.get("from", {}).get("emailAddress", {}).get("name", "") or ""
    body_preview = msg.get("bodyPreview", "") or ""
    has_attachments = msg.get("hasAttachments", False)

    sender_domain = from_addr.split("@")[1].lower() if "@" in from_addr else ""
    is_whitelisted = any(sender_domain.endswith(d) for d in WHITELISTED_SENDER_DOMAINS) if sender_domain else False

    score = 0.0
    reasons = []

    # Sender
    if not is_whitelisted:
        for pattern in SPAM_SENDER_PATTERNS:
            if pattern.search(from_addr):
                score += 0.3
                reasons.append(f"Suspicious TLD: {sender_domain}")
                break

        suspicious_tlds = {".xyz", ".top", ".buzz", ".club", ".icu", ".tk", ".ml", ".ga", ".cf", ".pw", ".work", ".click"}
        if sender_domain and any(sender_domain.endswith(tld) for tld in suspicious_tlds):
            score += 0.3
            reasons.append(f"Suspicious TLD: {sender_domain}")

    # Subject
    subject_hits = sum(1 for p in PHISHING_SUBJECT_PATTERNS if p.search(subject))
    threshold = 2 if is_whitelisted else 1
    if subject_hits >= threshold:
        score += min(subject_hits * 0.1, 0.3)
        reasons.append(f"Phishing subject ({subject_hits})")

    # Body
    body_hits = sum(1 for p in PHISHING_BODY_PATTERNS if p.search(body_preview))
    threshold = 3 if is_whitelisted else 1
    if body_hits >= threshold:
        score += min(body_hits * 0.1, 0.3)
        reasons.append(f"Phishing body ({body_hits})")

    # Brand impersonation
    if from_name and from_addr:
        known_brands = ["microsoft", "apple", "google", "amazon", "paypal", "netflix", "bank"]
        name_lower = from_name.lower()
        for brand in known_brands:
            if brand in name_lower and brand not in sender_domain:
                score += 0.4
                reasons.append(f"Impersonation: '{from_name}' from {sender_domain}")
                break

    # Attachments + urgency
    if has_attachments and subject_hits > 0:
        score += 0.2
        reasons.append("Attachment + urgency")

    if score >= 0.6:
        classification = "phishing"
    elif score >= 0.4:
        classification = "spam"
    elif score >= 0.2:
        classification = "suspicious"
    else:
        classification = "legitimate"

    return {
        "score": round(score, 2),
        "classification": classification,
        "reasons": reasons,
        "subject": subject[:80],
        "from": from_addr,
        "date": msg.get("receivedDateTime", "")[:10],
    }


def move_message(msg_id, dest_id, headers, dry_run):
    """Move a message to a folder. Returns True on success."""
    if dry_run:
        return True
    for attempt in range(3):
        try:
            resp = requests.post(
                f"{GRAPH_BASE}/me/messages/{msg_id}/move",
                headers={**headers, "Content-Type": "application/json"},
                json={"destinationId": dest_id},
                timeout=30,
            )
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 10))
                print(f"  Rate limited — waiting {retry_after}s")
                time.sleep(retry_after)
                continue
            return resp.status_code in (200, 201)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            time.sleep(5 * (attempt + 1))
    return False


def scan_inbox(headers, max_emails, filter_str=None):
    """Generator that yields messages from inbox in batches."""
    skip_token = None
    scanned = 0

    while max_emails == 0 or scanned < max_emails:
        batch_size = 50 if max_emails == 0 else min(50, max_emails - scanned)
        url = f"{GRAPH_BASE}/me/mailFolders/inbox/messages?$top={batch_size}&$select=id,subject,from,receivedDateTime,bodyPreview,hasAttachments&$orderby=receivedDateTime asc"
        if filter_str:
            url += f"&$filter={filter_str}"
        if skip_token:
            url = skip_token

        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            print("  Connection timeout — waiting 10s")
            time.sleep(10)
            continue
        if resp.status_code == 401:
            token = get_token()
            headers["Authorization"] = f"Bearer {token}"
            continue
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 10))
            print(f"  Rate limited — waiting {retry_after}s")
            time.sleep(retry_after)
            continue
        if resp.status_code != 200:
            print(f"  API error: {resp.status_code}")
            break

        data = resp.json()
        messages = data.get("value", [])
        if not messages:
            break

        skip_token = data.get("@odata.nextLink")

        for msg in messages:
            scanned += 1
            yield msg, scanned

        if not skip_token:
            break

        # Rate limit between batches
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description="Outlook Inbox Cleanup")
    parser.add_argument("--dry-run", action="store_true", help="Preview without moving")
    parser.add_argument("--mode", default="both", choices=["phishing", "marketing", "both"],
                        help="Cleanup mode (default: both)")
    parser.add_argument("--threshold", type=float, default=0.7, help="Phishing score threshold (default 0.7)")
    parser.add_argument("--max-emails", type=int, default=0, help="Max emails to scan (0=all)")
    parser.add_argument("--unread-only", action="store_true", help="Only process unread emails")
    args = parser.parse_args()

    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Get junk folder ID
    resp = requests.get(f"{GRAPH_BASE}/me/mailFolders/junkemail", headers=headers, timeout=15)
    if resp.status_code != 200:
        print("Could not find Junk folder")
        sys.exit(1)
    junk_id = resp.json()["id"]

    # Count inbox
    resp = requests.get(f"{GRAPH_BASE}/me/mailFolders/inbox", headers=headers, timeout=15)
    inbox_info = resp.json()
    total = inbox_info.get("totalItemCount", 0)
    unread = inbox_info.get("unreadItemCount", 0)
    print(f"Inbox: {total} total, {unread} unread")

    filter_str = "isRead eq false" if args.unread_only else None
    scan_total = unread if args.unread_only else total
    if args.max_emails:
        scan_total = min(scan_total, args.max_emails)

    print(f"Mode: {args.mode} | Scanning: {'unread only' if args.unread_only else 'all'} | Max: {scan_total} | Dry run: {args.dry_run}")
    print()

    marketing_moved = 0
    phishing_moved = 0
    total_scanned = 0
    move_failures = 0

    # Track unique marketing senders for summary
    marketing_senders = {}

    for msg, count in scan_inbox(headers, args.max_emails, filter_str):
        total_scanned = count
        moved = False

        # Marketing check
        if args.mode in ("marketing", "both"):
            is_mkt, reason = is_marketing(msg)
            if is_mkt:
                from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "?")
                sender_domain = from_addr.split("@")[1] if "@" in from_addr else from_addr
                marketing_senders[sender_domain] = marketing_senders.get(sender_domain, 0) + 1

                if move_message(msg["id"], junk_id, headers, args.dry_run):
                    marketing_moved += 1
                    moved = True
                else:
                    move_failures += 1

                if marketing_moved <= 50 or marketing_moved % 100 == 0:
                    subj = (msg.get("subject") or "")[:40]
                    print(f"  [MARKETING] {from_addr[:40]}: {subj}")

        # Phishing check (skip if already moved)
        if not moved and args.mode in ("phishing", "both"):
            result = score_email(msg)
            if result["score"] >= args.threshold:
                if move_message(msg["id"], junk_id, headers, args.dry_run):
                    phishing_moved += 1
                else:
                    move_failures += 1
                print(f"  [PHISHING score={result['score']}] {result['from'][:40]}: {result['subject'][:40]}")

        # Throttle moves to avoid rate limits
        if (marketing_moved + phishing_moved) % 20 == 0 and (marketing_moved + phishing_moved) > 0:
            time.sleep(2)

        # Progress
        if count % 1000 == 0:
            print(f"  ... {count} scanned — {marketing_moved} marketing, {phishing_moved} phishing moved")

    print()
    print(f"Done. Scanned {total_scanned} emails.")
    print(f"  Marketing moved: {marketing_moved}")
    print(f"  Phishing moved:  {phishing_moved}")
    if move_failures:
        print(f"  Move failures:   {move_failures}")
    if args.dry_run:
        print(f"  (DRY RUN — nothing was actually moved)")

    if marketing_senders:
        print(f"\nTop marketing senders:")
        for domain, count in sorted(marketing_senders.items(), key=lambda x: -x[1])[:20]:
            print(f"  {count:5d}  {domain}")


if __name__ == "__main__":
    main()
