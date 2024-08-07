import os, threading, sqlite3, sys

from datetime import datetime

class Cache(object):
	RESULT_SUCCESS=0
	RESULT_POTENTIAL=1
	RESULT_FAILURE=2
	RESULT_INEXISTANT=3
	TRANSLATE = {"success": RESULT_SUCCESS, "potential": RESULT_POTENTIAL, "failure": RESULT_FAILURE, "inexistant": RESULT_INEXISTANT}
	TRANSLATE_INV = {RESULT_SUCCESS : "success", RESULT_POTENTIAL: "potential", RESULT_FAILURE: "failure"}


	def __init__(self, cache_file='credmaster-cache.db'):
		self.lock = threading.Lock()
		self.cache_file = cache_file
		if os.path.exists(self.cache_file) and not os.path.isfile(self.cache_file):
			print(f"The cache path ({self.cache_file}) already exists and is not a file. Aborting")
			exit(1)

		conn = None
		try:
			conn = sqlite3.connect(self.cache_file)
		except:
			print("The cache file cannot be loaded by SQLite ! Aborting", file=sys.stderr)
			sys.exit(1)

		# result = {0: success, 1: potential, 2: failure, 3: user_does_not_exist}

		conn.cursor().execute('''
			CREATE TABLE IF NOT EXISTS cache (
				id INTEGER PRIMARY KEY,
				username TEXT NOT NULL,
				password TEXT NOT NULL,
				result INTEGER NOT NULL,
				output TEXT NOT NULL,
				plugin TEXT NOT NULL,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
			)
		''')
		conn.commit()

		self.cache = []
		recs = conn.cursor().execute('SELECT * from cache').fetchall()
		for data in recs:
			self.cache.append({
				"username": data[1],
				"password": data[2],
				"result": data[3],
				"output": data[4],
				"plugin": data[5],
				"timestamp": data[6]
			})

	def get_cursor(self):
		conn = sqlite3.connect(self.cache_file)
		return conn.cursor()

	def add_tentative(self, username, password, result, output, plugin, cursor=None):
		if cursor == None:
			conn = sqlite3.connect(self.cache_file)
			cursor = conn.cursor()
		self.lock.acquire()
		cursor.execute('INSERT INTO cache (username, password, result, output, plugin) VALUES (?, ?, ?, ?, ?)', (username, password, result, output, plugin))
		conn.commit()
		self.cache.append({
				"username": username,
				"password": password,
				"result": result,
				"output": output,
				"plugin": plugin,
				"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			})
		self.lock.release()

	def user_exists(self, username, plugin=None):
		tries = []
		for data in self.cache:
			if (plugin == None or data["plugin"] == plugin) and data["username"] == username and data["result"] == Cache.RESULT_INEXISTANT:
				tries.append(data)
		return len(tries) == 0

	def user_success(self, username, plugin=None):
		tries = []
		for data in self.cache:
			if (plugin == None or data["plugin"] == plugin) and data["username"] == username and data["result"] == Cache.RESULT_SUCCESS:
				tries.append(data)
		if len(tries) > 0:
			return True, tries[0]["password"]
		return False, None

	def query_creds(self, username, password, plugin=None):
		tries = []
		for data in self.cache:
			if (plugin == None or data["plugin"] == plugin) and data["username"] == username and data["password"] == password:
				tries.append(data)
		if len(tries) > 0:
			return tries[0]
		return None