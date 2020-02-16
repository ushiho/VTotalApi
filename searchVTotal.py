#!/usr/bin/python3.7

import requests, hashlib, argparse, re, sys
from os import path

class vtAPI:

	def __init__(self):
		self.api = '83aa6d7279952cc5d7d4088249099683d21577d05d09dd2a5a8a7a36829df8a2'
		self.base = 'https://www.virustotal.com/vtapi/v2/'

	def getReport(self, md5):
		url = self.base + 'file/report'
		params = {'apikey': self.api, 'resource': md5}
		response = requests.get(url, params=params)
		jdata = response.json()
		return jdata

def md5sum(filename, blocksize=65536):
	if checkPathIfExist:
	    hash = hashlib.md5()
	    with open(filename, "rb") as f:
	        for block in iter(lambda: f.read(blocksize), b""):
	            hash.update(block)
	    return hash.hexdigest()
	else:
		print("The path is not exist or is not a file.")
		print("Please give a correct path and try again.")
		sys.exit(1)

def checkMD5(checkval):
	if re.match(r"([a-fA-F\d]{32})", checkval) == None:
		md5 = md5sum(checkval)
		return md5.upper()
	else: 
		return checkval.upper()

def showResults(report, md5):
	if report['response_code'] == 0:
		print(md5 + " -- Not Found in VT")
		return 0
	print("\tResults for MD5: ",report['md5'],"\n\tDetected by: ",report['positives'],'/',report['total'])
	print("\tScans Results:")
	print('\t'+('-'*60))
	for scanedBy, results in report['scans'].items():
		print("\t*Name: ", scanedBy)
		print("\t\t***Detected: ", results['detected'])
		print("\t\t***Version: ", results['version'])
		print("\t\t***Result: ", results['result'])
		print("\t\t***Update: ", results['update'])
	print('\t'+('-'*60))

def checkPathIfExist(path):
	return (path.exists(path) and path.isfile(path))

def main():
	parser = argparse.ArgumentParser(description="Search from VirusTotal")
	parser.add_argument("HashorPath", help="Enter the MD5 Hash or Path to File")
	parser.add_argument("-s", "--search", action="store_true", help="Search VirusTotal")
	
	if len(sys.argv)<=2:
		parser.print_help()
		sys.exit(1)
	args = parser.parse_args()
	vt = vtAPI()
	md5 = checkMD5(args.HashorPath)
	if args.search:
		showResults(vt.getReport(md5), md5)
		vt.getReport(md5)

if __name__ == '__main__':
	main()
