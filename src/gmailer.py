#!/usr/bin/python3

import json
import logging
import sqlite3
import time
from email.utils import parseaddr
from pathlib import Path

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import BatchHttpRequest

MAX_TPS = 50  # google batch limit (50TPS for messages.get and messages.list)

_BASE = Path(__file__).parent


class Gmailer:
    """
    Gmail client for inbox cleanup and general management.
    Use with caution, has the big guns as far as perms...
    """

    def __get_or_update_credentials(self, SCOPES):
        TOKEN = _BASE / ".env/token.json"
        CREDENTIALS = _BASE / ".env/credentials.json"
        creds = None

        if TOKEN.exists():
            creds = Credentials.from_authorized_user_file(TOKEN, SCOPES)

        # not exists or invalid, get creds
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    TOKEN.unlink()
                    creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS, SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(TOKEN, "w") as token:
                token.write(creds.to_json())
        return creds

    def __init__(self, scopes=["https://mail.google.com/"]):
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

        self.SCOPES = scopes
        self.userId = "me"
        self.service = build(
            serviceName="gmail",
            version="v1",
            credentials=self.__get_or_update_credentials(self.SCOPES),
        )

    ###########################################################################
    # Request convenience methods
    ###########################################################################

    def __list_messages_request(self):
        return (
            self.service.users()
            .messages()
            .list(userId="me", maxResults=500, includeSpamTrash=False)
        )

    def __get_next_page_request(self, req, res):
        return self.service.users().messages().list_next(req, res)

    def __get_sender_request(self, message_id: str) -> BatchHttpRequest:
        return (
            self.service.users()
            .messages()
            .get(
                userId=self.userId,
                id=message_id,
                format="metadata",
                metadataHeaders=["From", "Subject"],
            )
        )

    ###########################################################################
    # Regular Shmegular facilitations

    def get(self, userId="me", msgId=None):
        return self.service.users().messages().get(userId=userId, id=msgId).execute()

    def safe_delete(self, userId="me", msgId=None):
        return self.service.users().messages().trash(userId=userId, id=msgId).execute()

    def get_message_ids(self, cached_ok=False) -> list[str]:
        cache_path = _BASE / "message_ids.json"
        # cached check
        if cached_ok and cache_path.exists():
            print("found existing message ids. loading...")
            time.sleep(2)
            with open(cache_path, "r") as f:
                return json.load(f)

        message_ids = []
        req = self.__list_messages_request()

        while req is not None:
            try:
                res = req.execute()
                messages = res.get("messages", [])
                ids = [m["id"] for m in messages]
                print(
                    f"//:3//Adding {len(ids)} ids to our list...total is {len(message_ids)}"
                )
                message_ids.extend(ids)
                req = self.__get_next_page_request(req, res)

            except HttpError as error:
                print(f"An error occurred: {error}")
                break

        return message_ids

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(_BASE / "messages.db", check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id            TEXT PRIMARY KEY,
                thread_id     TEXT,
                sender        TEXT,
                subject       TEXT,
                internal_date INTEGER,
                size_estimate INTEGER,
                label_ids     TEXT,
                fetched_at    INTEGER
            )
        """)
        conn.commit()
        return conn

    def _upsert_messages(self, conn: sqlite3.Connection, rows: list[dict]):
        conn.executemany(
            "INSERT OR REPLACE INTO messages VALUES (:id, :thread_id, :sender, :subject, :internal_date, :size_estimate, :label_ids, :fetched_at)",
            rows,
        )
        conn.commit()

    def _parse_message(self, response: dict) -> dict:
        headers = response.get("payload", {}).get("headers", [])
        from_header = next((h["value"] for h in headers if h["name"].lower() == "from"), None)
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
        _, sender = parseaddr(from_header) if from_header else (None, "unknown@email.address")
        return {
            "id": response.get("id"),
            "thread_id": response.get("threadId"),
            "sender": sender or "unknown@email.address",
            "subject": subject,
            "internal_date": int(response.get("internalDate", 0)),
            "size_estimate": response.get("sizeEstimate"),
            "label_ids": json.dumps(response.get("labelIds", [])),
            "fetched_at": int(time.time() * 1000),
        }

    def fetch_and_store(self, message_ids: list[str], flush_every=100):
        conn = self._init_db()
        pending = []
        batch_number = 0

        def callback(request_id: str, response: dict, exception):
            if response is None:
                return
            pending.append(self._parse_message(response))

        for i in range(0, len(message_ids), MAX_TPS):
            batch: BatchHttpRequest = self.service.new_batch_http_request(callback=callback)
            for id in message_ids[i : i + MAX_TPS]:
                batch.add(self.__get_sender_request(id))
            batch_number += 1
            print(f"sending batch no. {batch_number}")
            batch.execute()
            time.sleep(5)
            if batch_number % flush_every == 0:
                self._upsert_messages(conn, pending)
                pending.clear()

        if pending:
            self._upsert_messages(conn, pending)
        conn.close()

    def get_top_senders(self, ranks=20) -> list[tuple[str, int]]:
        conn = self._init_db()
        rows = conn.execute(
            "SELECT sender, COUNT(*) as cnt FROM messages GROUP BY sender ORDER BY cnt DESC LIMIT ?",
            (ranks,),
        ).fetchall()
        conn.close()
        return rows

    def delete_by_sender(self, email: str, dry_run: bool = True):
        conn = self._init_db()
        ids = [r[0] for r in conn.execute("SELECT id FROM messages WHERE sender = ?", (email,)).fetchall()]
        conn.close()
        if not ids:
            print(f"No messages found for {email}")
            return
        if dry_run:
            print(f"Would delete {len(ids)} messages from {email}")
            print(f"Sample IDs: {ids[:3]}")
            return
        for i, id in enumerate(ids, 1):
            self.safe_delete(msgId=id)
            if i % 50 == 0:
                print(f"Deleted {i}/{len(ids)}...")
        print(f"Done. Deleted {len(ids)} messages from {email}.")

    def delete_by_sender_direct(self, email: str, dry_run: bool = True):
        ids = []
        req = self.service.users().messages().list(
            userId=self.userId, q=f"from:{email}", maxResults=500
        )
        while req is not None:
            res = req.execute()
            ids.extend(m["id"] for m in res.get("messages", []))
            req = self.service.users().messages().list_next(req, res)
        if not ids:
            print(f"No messages found for {email}")
            return
        if dry_run:
            print(f"Would delete {len(ids)} messages from {email}")
            print(f"Sample IDs: {ids[:3]}")
            return
        for i, id in enumerate(ids, 1):
            self.safe_delete(msgId=id)
            if i % 50 == 0:
                print(f"Deleted {i}/{len(ids)}...")
        print(f"Done. Deleted {len(ids)} messages from {email}.")

    @staticmethod
    def to_json(res):
        return json.dumps(res, sort_keys=True, indent=4)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Gmailer CLI")
    parser.add_argument("--top", type=int, default=20, metavar="N", help="Print top N senders")
    parser.add_argument("--delete", metavar="EMAIL", help="Delete all messages from EMAIL")
    parser.add_argument("--delete-direct", metavar="EMAIL", help="Delete all messages from EMAIL via live API query (no DB required)")
    parser.add_argument("--confirm", action="store_true", help="Required to execute deletion")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted")
    args = parser.parse_args()

    g = Gmailer()

    if args.delete:
        dry = not args.confirm or args.dry_run
        g.delete_by_sender(args.delete, dry_run=dry)
    elif args.delete_direct:
        dry = not args.confirm or args.dry_run
        g.delete_by_sender_direct(args.delete_direct, dry_run=dry)
    else:
        for email, count in g.get_top_senders(args.top):
            print(f"{count:>6}  {email}")
