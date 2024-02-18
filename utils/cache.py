import os, threading, sqlite3

class Cache(object):
	RESULT_SUCCESS=0
	RESULT_POTENTIAL=1
	RESULT_FAILURE=2
	RESULT_INEXISTANT=3
	TRANSLATE = {"success": RESULT_SUCCESS, "potential": RESULT_POTENTIAL, "failure": RESULT_FAILURE, "inexistant": RESULT_INEXISTANT}
	TRANSLATE_INV = {RESULT_SUCCESS : "success", RESULT_POTENTIAL: "potential", RESULT_FAILURE: "failure"}


	def __init__(self, cache_folder='.credmaster'):
		self.lock = threading.Lock()
		self.cache_folder = cache_folder
		if os.path.exists(self.cache_folder):
			if not os.path.isdir(self.cache_folder):
				print(f"The state path ({self.cache_folder}) already exists and is not a folder. Aborting")
				exit(1)
		else:
			os.mkdir(self.cache_folder)
		
		conn = sqlite3.connect(os.path.join(self.cache_folder, "cache.db"))

		# result = {0: success, 1: potential, 2: failure, 3: user_does_not_exist}

		conn.cursor().execute('''
			CREATE TABLE IF NOT EXISTS cache (
				id INTEGER PRIMARY KEY,
				username TEXT NOT NULL,
				password TEXT NOT NULL,
				result INTEGER NOT NULL,
				output TEXT NOT NULL
			)
		''')
		conn.commit()
	
	def get_cursor(self):
		conn = sqlite3.connect(os.path.join(self.cache_folder, "cache.db"))
		return conn.cursor()
	
	def add_tentative(self, username, password, result, output, cursor=None):
		if cursor == None:
			conn = sqlite3.connect(os.path.join(self.cache_folder, "cache.db"))
			cursor = conn.cursor()
		self.lock.acquire()
		cursor.execute('INSERT INTO cache (username, password, result, output) VALUES (?, ?, ?, ?)', (username, password, result, output))
		conn.commit()
		self.lock.release()
	
	def user_exists(self, username, cursor=None):
		if cursor == None:
			conn = sqlite3.connect(os.path.join(self.cache_folder, "cache.db"))
			cursor = conn.cursor()
		cursor.execute('SELECT username FROM cache WHERE username = ? and result = ?', (username, Cache.RESULT_INEXISTANT))
		recs = cursor.fetchall()
		return len(recs) == 0

	def user_success(self, username, cursor=None):
		if cursor == None:
			conn = sqlite3.connect(os.path.join(self.cache_folder, "cache.db"))
			cursor = conn.cursor()
		cursor.execute('SELECT password FROM cache WHERE username = ? and result = ?', (username, Cache.RESULT_SUCCESS))
		recs = cursor.fetchall()
		if len(recs) > 0:
			return True, recs[0][0]
		return False, None
	
	def query_creds(self, username, password, cursor=None):
		if cursor == None:
			conn = sqlite3.connect(os.path.join(self.cache_folder, "cache.db"))
			cursor = conn.cursor()
		cursor.execute('SELECT result, output FROM cache WHERE username = ? and password = ?', (username, password))
		recs = cursor.fetchall()
		if len(recs) > 0:
			return recs[0]
		return None