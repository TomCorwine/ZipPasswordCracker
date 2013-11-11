# zipPasswordCracker
# version 0.8

# Simple encrypted zip file password dictionary and bruce-force cracker
# Original script from https://gist.github.com/23ars/6613420

import zipfile
import argparse
from multiprocessing.pool import ThreadPool
import string
import itertools
import sys
import os

def __exit(string):
	global parser
	print string + '\n' + parser.print_help()
	exit(1)

def __output(string):
	sys.stdout.write('\r\x1b[K' + string)
	sys.stdout.flush()

def __extractFile(zipFile, password):
	try:
		zipFile.extractall(pwd=password)
		return password
	except:
		return None

def __generatePasswords(characterSet, minLength, maxlength):
    return (''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(characterSet, repeat=i)
        for i in range(minLength, maxlength + 1)))

def __checkPasswords(passwordList, zipFile):
	pool = ThreadPool(processes=16)
	stop = False
	while stop is False:
		for password in passwordList:
			global quiet
			if quiet is False:
				__output(password)
			thread = pool.apply_async(__extractFile, (zipFile, password))		
			result = thread.get()
			if result is not None:
				stop = True
				return result
		stop = True
	return None

def main():
	global parser
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--file', dest='zipFile', metavar='<filename>', required=True, type=str,
		help='path to zip file to attack')
	parser.add_argument('-v', '--version', action='version', version='v0.8')
	parser.add_argument('-d', '--dictionary-file', dest='dictionaryFile', metavar='<filename>',
		type=str, help='path to password dictionary file for dictionary attacks (one password per line)')
	parser.add_argument('-s', '--start-length', dest='minLength', metavar='N', default=1, type=int,
		help='minimum password character length for brute-force attacks - defaults to 1')
	parser.add_argument('-e', '--end-length', dest='maxLength', metavar='N', default=6, type=int,
		help='maximum password character length for brute-force attacks - defaults to 6')
	parser.add_argument('--no-lower-case', dest='noLowerCase', action='store_true',
		help='do not use lower-case letters in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--no-upper-case', dest='noUpperCase', action='store_true',
		help='do not use upper-case letters in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--no-numbers', dest='noNumbers', action='store_true',
		help='do not use numbers (0-9) in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--no-punctuation', dest='noPunctuation', action='store_true',
		help='do not use punctuation in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--use-character-set', dest='charactersSet', metavar='<string of chacters>', type=list,
		help='use characters from supplied set instead of built-in set - above character set options are ignored.')
	parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
		help='do not print passwords to stdout')
	args = parser.parse_args()

	global quiet
	quiet = args.quiet
	dictionary = None
	zipFile = zipfile.ZipFile(args.zipFile)
	minLength = args.minLength
	maxLength = args.maxLength
	noLowerCase = args.noLowerCase
	noUpperCase = args.noUpperCase
	noNumbers = args.noNumbers
	noPunctuation = args.noPunctuation
	charactersSet = args.charactersSet

	if maxLength < minLength:
		__exit('--end-length can not be lower than --start-length.')

	if args.dictionaryFile is not None:
		file = open(args.dictionaryFile, 'r')
		dictionary = []
		for line in file.readlines():
			dictionary.append(line.strip('\n\r'))

	if charactersSet is None: # if character set was supplied on command line, skip this
		charactersSet = ''
		if noLowerCase is False:
			charactersSet = charactersSet + string.ascii_lowercase
		if noUpperCase is False:
			charactersSet = charactersSet + string.ascii_uppercase
		if noNumbers is False:
			charactersSet = charactersSet + string.digits
		if noPunctuation is False:
			charactersSet = charactersSet + string.punctuation

	if dictionary is None and charactersSet is None:
		__exit('Nothing to do as no dictionary was specified and all brute-forcing options are disabled.')

	password = None
	if dictionary is not None:
		print 'Trying dictionary...'
		password = __checkPasswords(dictionary, zipFile)
	if charactersSet is not None and password is None:
		print 'Trying brute-force...'
		passwords = __generatePasswords(charactersSet, minLength, maxLength)
		password = __checkPasswords(passwords, zipFile)
	if password is None:
		__output('Sorry, not able to crack file. Try changing some options such as setting --end-length to a higher number.\n')
	else:
		__output('[+] Found password: ' + password + '\n')
	exit(0)

if '__main__' == __name__:
	main()
