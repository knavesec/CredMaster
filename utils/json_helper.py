import json
import os

# Json functions for getting path then reading contents of config variables
def get_path():
	"""
	A function to get the current path to bot.py

	Returns:
	 - cwd (string) : Path to bot.py directory
	"""
	cwd = os.getcwd()
	#cwd = Path(__file__).resolve().parent[1]
	cwd = str(cwd)
	return cwd


def read_json(filename):
	"""
	A function to read a json file and return the data.

	Params:
	 - filename (string) : The name of the file to open

	Returns:
	 - data (dict) : A dict of the data in the file
	"""
	cwd = get_path()
	with open(cwd + "/" + filename + ".json", "r") as file:
		data = json.load(file)
	return data


def write_json(data, filename):
	"""
	A function used to write data to a json file

	Params:
	 - data (dict) : The data to write to the file
	 - filename (string) : The name of the file to write to
	"""
	cwd = get_path()
	with open(cwd + "/" + filename + ".json", "r") as file:
		data = json.load(file)
	return data
