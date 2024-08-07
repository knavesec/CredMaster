import os, argparse, sqlite3

def get_successes(cache_file):
	conn = sqlite3.connect(cache_file)
	cursor = conn.cursor()
	cursor.execute('SELECT username, password FROM cache WHERE result = 0')
	recs = cursor.fetchall()
	if len(recs) == 0:
		return None
	return recs

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--file", type=str, default="credmaster-cache.db", help="Path of the credmaster cache file")
	args = parser.parse_args()
	
	successes = get_successes(args.file)
	if successes is None:
		print("No successes for now, come back later...")
	else:
		print(f"{len(successes)} successes for now!")
		print("")
		for u,p in successes:
			print(f"{u}:{p}")
