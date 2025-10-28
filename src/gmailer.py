#!/usr/bin/python3

import json
import logging
import os.path
import time
from collections import Counter, defaultdict
from email.utils import parseaddr

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import BatchHttpRequest
from ratelimit import limits, sleep_and_retry

MAX_TPS = 50  # google batch limit (50TPS for messages.get and messages.list)


class Gmailer:
    """
    Gmail client for inbox cleanup and general management.
    Use with caution, has the big guns as far as perms...
    """

    def __get_or_update_credentials(self, SCOPES):
        TOKEN = ".env/token.json"
        CREDENTIALS = ".env/credentials.json"
        creds = None

        if os.path.exists(TOKEN):
            creds = Credentials.from_authorized_user_file(TOKEN, SCOPES)

        # not exists or invalid, get creds
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    os.remove(TOKEN)
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
    # TODO add more
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
                metadataHeaders=["From"],
            )
        )

    ###########################################################################
    # Regular Shmegular facilitations

    def get(self, userId="me", msgId=None):
        return self.service.users().messages().get(userId=userId, id=msgId).execute()

    def safe_delete(self, userId="me", msgId=None):
        return self.service.users().messages().trash(userId=userId, id=msgId).execute()

    @sleep_and_retry
    @limits(calls=MAX_TPS, period=1)
    def get_message_ids(self, cached_ok=False) -> list[str]:
        # cached check
        if cached_ok and os.path.exists("message_ids.json"):
            print("found existing message ids. loading...")
            time.sleep(2)
            with open("message_ids.json", "r") as f:
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

    def get_sender_counts(
        self, message_ids: list[str], batch_size=MAX_TPS
    ) -> dict[str, list[str]]:
        """
        batch fetches "From" values for a list of messages
        exponential retry backoff
        """
        sender_map = defaultdict(list)
        pay_structure = None

        def callback(request_id: str, response: dict, exception):
            if pay_structure is not None:
                print("then we can talk")
            email, id = self.get_emails_from_metadata(response)
            sender_map[email].append(id)

        for i in range(0, len(message_ids), MAX_TPS):
            batch: BatchHttpRequest = self.service.new_batch_http_request(
                callback=callback
            )
            id_chunk: list = message_ids[i : i + MAX_TPS]
            for id in id_chunk:
                req = self.__get_sender_request(id)
                batch.add(req)
            print(f"sending batch no. {i // MAX_TPS + 1}")
            batch.execute()
            time.sleep(
                5
            )  # rudimentary delay while we implement rate limiting on this method

        return sender_map

    def get_emails_from_metadata(self, message_metadata: dict):
        """
        Extracts a list of sender email addresses from the message metadata.
        """
        print(f"mmd:{message_metadata}")
        headers = message_metadata.get("payload", {}).get("headers", [])
        id = message_metadata.get("id")
        from_header = next(
            (h["value"] for h in headers if h["name"].lower() == "from"), None
        )
        if from_header:
            # parseaddr returns a (name, email) tuple, we want the email part
            _, email_addr = parseaddr(from_header)
            if email_addr:
                return email_addr, id

        return "unknown@email.address", id

    @staticmethod
    def to_json(res):
        return json.dumps(res, sort_keys=True, indent=4)

    @staticmethod
    def save_as(file_name, content):
        with open(file_name, "w") as f:
            json.dump(content, f, indent=4)

    def get_top_senders(self, ranks=20) -> list[tuple[str, int]]:
        # no need to spin the machines
        if os.path.exists("sender_counts.json"):
            print("found existing sender counts. loading...")
            time.sleep(2)
            with open("sender_counts.json", "r") as f:
                return json.load(f)

        # ok spin em
        message_ids = self.get_message_ids()
        self.save_as("message_ids.json", message_ids)

        sender_emails = self.get_sender_counts(message_ids)
        sender_counts = Counter(
            {email: len(ids) for email, ids in sender_emails.items()}
        )
        # most_common() returns a list of (email, count) tuples, sorted by count
        sorted_senders = sender_counts.most_common()

        self.save_as("sender_counts.json", sender_counts)
        print(f"saving {len(sender_counts)} sender_counts.")
        return sorted_senders
