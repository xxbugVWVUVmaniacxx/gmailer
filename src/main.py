import json
import logging
import os.path
import random
import time
from collections import Counter
from email.utils import parseaddr

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import BatchHttpRequest


class Util:
    @staticmethod
    def get_or_update_credentials(SCOPES):
        TOKEN = "token.json"
        CREDENTIALS = "credentials.json"

        if os.path.exists(TOKEN):
            creds = Credentials.from_authorized_user_file(TOKEN, SCOPES)

        # not exists or invalid, get creds
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS, SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(TOKEN, "w") as token:
                token.write(creds.to_json())
        return creds

    @staticmethod
    def toJson(res):
        return json.dumps(res, sort_keys=True, indent=4)


class Gmailer:
    def __init__(self, scopes=["https://www.main.google.com"]):
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

        self.SCOPES = scopes
        self.service = build(
            serviceName="gmail",
            version="v1",
            credentials=Util.get_or_update_credentials(self.SCOPES),
        )

    def build_get_messages_request(
        self, userId="me", maxResults=500, includeSpamTrash=False
    ):
        return (
            self.service.users().messages().list(userId, maxResults, includeSpamTrash)
        )

    def build_get_more_messages_request(self, previous_request, previous_response):
        return (
            self.service.users()
            .messages()
            .list_next(
                previous_request=previous_request, previous_response=previous_response
            )
        )

    def get_all_messages(self, request):
        all_messages = []
        while request is not None:
            response = request.execute()
            messages = response.get("messages", [])
            all_messages.extend(messages)
            request = self.build_get_more_messages_request(request, response)
        return all_messages

    def save_as(self, file_name, content):
        with open(file_name, "w") as f:
            json.dump(content, f, indent=4)

    def get_sender_counts(self, sorted_senders):
        # Convert list of tuples to a more readable list of dicts for JSON
        json_output = [
            {"sender": email, "count": count} for email, count in sorted_senders
        ]
        self.save_as("sender_counts.json", json_output)
        print(
            f"Saved sender counts for {len(sorted_senders)} unique senders to sender_counts.json"
        )

    def get_message_metadata(self, messages):
        return get_message_metadata_in_batch(self.service, messages, ["From"])

    def get_senders_by_count(
        self,
    ):
        request = self.build_get_messages_request(self.service)

        all_messages = self.get_all_messages(request)
        if not all_messages:
            print("No messages found.")
            return

        message_metadata = self.get_message_metadata_in_batch(all_messages)
        if not message_metadata:
            print("no message metadata")
            return

        sender_emails = self.get_senders_from_metadata(message_metadata)

        sender_counts = Counter(sender_emails)
        # most_common() returns a list of (email, count) tuples, sorted by count
        sorted_senders = sender_counts.most_common()

        self.save_as("sender_counts.json", sorted_senders)

    def get_message_metadata_in_batch(self, messages, headers=None):
        """
        Fetches metadata for a list of messages using batch requests for efficiency,
        with exponential backoff for rate-limiting errors.
        """
        metadata = {}
        messages_to_process = list(messages)
        max_retries = 5

        for retry_attempt in range(max_retries):
            failed_requests_map = {}

            def callback(request_id, response, exception):
                if exception is not None:
                    # Retry on 403 (user rate limit) and 429 (project rate limit).
                    if isinstance(exception, HttpError) and exception.resp.status in [
                        403,
                        429,
                    ]:
                        failed_requests_map[request_id] = True
                    else:
                        print(f"Error fetching message {request_id}: {exception}")
                else:
                    metadata[request_id] = response

            # Process messages in chunks of 100, as the batch API has a limit.
            for i in range(0, len(messages_to_process), 100):
                batch: BatchHttpRequest = self.service.new_batch_http_request(
                    callback=callback
                )
                message_chunk: list = messages_to_process[i : i + 100]
                for message in message_chunk:
                    msg_id: str = message["id"]
                    batch.add(
                        self.service.users()
                        .messages()
                        .get(
                            userId="me",
                            id=msg_id,
                            format="metadata",
                            metadataHeaders=headers,
                        ),
                        request_id=msg_id,
                    )
                batch.execute()

            if not failed_requests_map:
                return metadata  # Success

            messages_to_process = [
                m for m in messages_to_process if m["id"] in failed_requests_map
            ]
            sleep_time = (2**retry_attempt) + random.random()
            print(
                f"Rate limit exceeded. Retrying {len(messages_to_process)} requests in {sleep_time:.2f} seconds..."
            )
            time.sleep(sleep_time)

        print(
            f"Could not fetch all messages after {max_retries} retries. {len(messages_to_process)} requests failed."
        )

        return metadata

    def get_senders_from_metadata(self, message_metadata):
        """
        Extracts a list of sender email addresses from the message metadata.
        """
        sender_emails = []
        for msg_data in message_metadata.values():
            headers = msg_data.get("payload", {}).get("headers", [])
            from_header = next(
                (h["value"] for h in headers if h["name"].lower() == "from"), None
            )
            if from_header:
                # parseaddr returns a (name, email) tuple, we want the email part
                name, email_addr = parseaddr(from_header)
                if email_addr:
                    sender_emails.append(email_addr)
        return sender_emails
