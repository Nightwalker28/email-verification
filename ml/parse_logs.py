import argparse
import csv
import json
import os
import re
from typing import Dict, Optional


RE_TASK_RECEIVED = re.compile(r"Task .*?\[(?P<task_id>[0-9a-f-]+)\] received")
RE_TASK_START = re.compile(
    r"Task (?P<task_id>[0-9a-f-]+): Starting email_verify_task for email: "
    r"(?P<email>[^,]+), user_id: (?P<user_id>\d+), force_live: (?P<force_live>True|False)"
)
RE_VERIF_START = re.compile(
    r"Starting verification for email: (?P<email>\S+) \(Force live: (?P<force_live>True|False)\)"
)
RE_CONNECT_MX = re.compile(r"Connecting to (?P<mx_host>[^ ]+)\.")
RE_MX_ERROR = re.compile(r"MX record (?P<mx_host>[^ ]+) for (?P<email>[^:]+):")
RE_TEMP_ERROR = re.compile(r"TempError: (?P<temp_error>True|False)")
RE_SMTP_CODE = re.compile(r"Code: (?P<smtp_code>\d+)")
RE_RESULT_COMPLETED = re.compile(
    r"Verification for (?P<email>\S+) completed in (?P<duration>[0-9.]+)s\. "
    r"Result: (?P<result>[^,]+), Source: (?P<source>.+)"
)
RE_RESULT_TASK = re.compile(
    r"perform_email_verification completed for (?P<email>.+?)\. Result: \{(?P<details>.*)\}"
)
RE_TASK_SUCCESS = re.compile(
    r"Task pages\.schedule\.email_verify_task\[(?P<task_id>[0-9a-f-]+)\] succeeded.*: \{(?P<payload>.*)\}"
)

DETAIL_FIELDS = ("result", "provider", "role_based", "accept_all", "full_inbox", "temporary_mail")


def parse_details(details_text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for field in DETAIL_FIELDS:
        match = re.search(rf"{field}['\"]: ['\"]([^'\"]+)['\"]", details_text)
        if match:
            parsed[field] = match.group(1)
    return parsed


def parse_payload(payload_text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    email_match = re.search(r"email['\"]: ['\"]([^'\"]+)['\"]", payload_text)
    if email_match:
        parsed["email"] = email_match.group(1)
    details_match = re.search(r"details['\"]: \{(?P<details>.*)\}", payload_text)
    if details_match:
        parsed.update(parse_details(details_match.group("details")))
    return parsed


def domain_from_email(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return None
    return email.split("@", 1)[1].lower()


def finalize_row(task_id: str, task: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    email = task.get("email")
    return {
        "task_id": task_id,
        "timestamp": task.get("timestamp"),
        "email": email,
        "domain": domain_from_email(email),
        "user_id": task.get("user_id"),
        "force_live": task.get("force_live"),
        "result": task.get("result"),
        "provider": task.get("provider"),
        "role_based": task.get("role_based"),
        "accept_all": task.get("accept_all"),
        "full_inbox": task.get("full_inbox"),
        "temporary_mail": task.get("temporary_mail"),
        "smtp_code": task.get("smtp_code"),
        "mx_host": task.get("mx_host"),
        "temp_error": task.get("temp_error"),
        "duration_s": task.get("duration_s"),
        "source": task.get("source"),
    }


def parse_log_file(input_path: str) -> Dict[str, Dict[str, Optional[str]]]:
    tasks: Dict[str, Dict[str, Optional[str]]] = {}
    task_order = []

    with open(input_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            log_text = record.get("log", "")
            timestamp = record.get("time")
            if not log_text:
                continue

            match = RE_TASK_RECEIVED.search(log_text)
            if match:
                task_id = match.group("task_id")
                if task_id not in tasks:
                    tasks[task_id] = {}
                    task_order.append(task_id)
                tasks[task_id]["timestamp"] = timestamp

            match = RE_TASK_START.search(log_text)
            if match:
                task_id = match.group("task_id")
                if task_id not in tasks:
                    tasks[task_id] = {}
                    task_order.append(task_id)
                tasks[task_id].update(
                    {
                        "email": match.group("email"),
                        "user_id": match.group("user_id"),
                        "force_live": match.group("force_live"),
                        "timestamp": timestamp,
                    }
                )

            match = RE_VERIF_START.search(log_text)
            if match:
                email = match.group("email")
                force_live = match.group("force_live")
                for task in tasks.values():
                    if task.get("email") == email and not task.get("force_live"):
                        task["force_live"] = force_live
                        break

            match = RE_CONNECT_MX.search(log_text)
            if match:
                mx_host = match.group("mx_host")
                for task in tasks.values():
                    if task.get("mx_host") is None:
                        task["mx_host"] = mx_host

            match = RE_MX_ERROR.search(log_text)
            if match:
                mx_host = match.group("mx_host")
                email = match.group("email").strip()
                for task in tasks.values():
                    if task.get("email") == email:
                        task["mx_host"] = mx_host
                        break

            match = RE_TEMP_ERROR.search(log_text)
            if match:
                temp_error = match.group("temp_error")
                for task in tasks.values():
                    if task.get("temp_error") is None:
                        task["temp_error"] = temp_error

            match = RE_SMTP_CODE.search(log_text)
            if match:
                smtp_code = match.group("smtp_code")
                for task in tasks.values():
                    if task.get("smtp_code") is None:
                        task["smtp_code"] = smtp_code

            match = RE_RESULT_COMPLETED.search(log_text)
            if match:
                email = match.group("email")
                for task in tasks.values():
                    if task.get("email") == email:
                        task.update(
                            {
                                "duration_s": match.group("duration"),
                                "result": match.group("result"),
                                "source": match.group("source"),
                            }
                        )
                        break

            match = RE_RESULT_TASK.search(log_text)
            if match:
                email = match.group("email")
                details = parse_details(match.group("details"))
                for task in tasks.values():
                    if task.get("email") == email:
                        task.update(details)
                        break

            match = RE_TASK_SUCCESS.search(log_text)
            if match:
                task_id = match.group("task_id")
                payload = parse_payload(match.group("payload"))
                if task_id not in tasks:
                    tasks[task_id] = {}
                    task_order.append(task_id)
                if tasks[task_id].get("timestamp") is None:
                    tasks[task_id]["timestamp"] = timestamp
                tasks[task_id].update(payload)

    return {task_id: tasks[task_id] for task_id in task_order}


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse valid8 celery JSON logs into CSV.")
    parser.add_argument("input", help="Path to valid8-celery-json.log")
    parser.add_argument(
        "--output",
        default="ml/valid8_logs.csv",
        help="Output CSV path (default: ml/valid8_logs.csv)",
    )
    args = parser.parse_args()

    tasks = parse_log_file(args.input)
    fieldnames = [
        "task_id",
        "timestamp",
        "email",
        "domain",
        "user_id",
        "force_live",
        "result",
        "provider",
        "role_based",
        "accept_all",
        "full_inbox",
        "temporary_mail",
        "smtp_code",
        "mx_host",
        "temp_error",
        "duration_s",
        "source",
    ]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for task_id, task in tasks.items():
            writer.writerow(finalize_row(task_id, task))


if __name__ == "__main__":
    main()
