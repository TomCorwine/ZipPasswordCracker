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

def __extractFile(zipFile, password):
	try:
		zipFile.extractall(pwd=password)
		return password
	except:
		return None

def __generatePassword(characterSet, minLength, maxlength):
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
				sys.stdout.write('\r\x1b[K' + password)
				sys.stdout.flush()
			thread = pool.apply_async(__extractFile, (zipFile, password))		
			result = thread.get()
			if result is not None:
				stop = True
				return result
		stop = True
	return None

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--file', dest='zipFile', metavar='<filename>', required=True, type=str,
		help='path to zip file to attack')
	parser.add_argument('-v', '--version', action='version', version='v0.8')
	parser.add_argument('-d', '--dictionary-file', dest='dictionaryFile', metavar='<filename>',
		type=str, help='path to password dictionary file for dictionary attacks (one password per line)')
	parser.add_argument('-s', '--start-length', dest='minLength', metavar='N', default=1, type=int,
		help='minimum password character length for brute-force attacks')
	parser.add_argument('-e', '--end-length', dest='maxLength', metavar='N', default=6, type=int,
		help='maximum password character length for brute-force attacks')
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
		print 'maxLength can not be lower than minLength.'
		print parser.print_help()
		exit(1)
	if args.dictionaryFile is not None:
		file = open(args.dictionaryFile, 'r')
		dictionary = []
		for line in file.readlines():
			dictionary.append(line.strip('\n\r'))

	if charactersSet is None: # if character set was supplied on command line, skip this
		if noLowerCase is False:
			charactersSet = charactersSet + string.ascii_lowercase
		if noUpperCase is False:
			charactersSet = charactersSet + string.ascii_uppercase
		if noNumbers is False:
			charactersSet = charactersSet + string.digits
		if noPunctuation is False:
			charactersSet = charactersSet + string.punctuation

	if dictionary is None and charactersSet is None:
		print 'Nothing to do as no dictionary was specified and all brute-forcing options are disabled.'
		exit(1)

	password = None
	if dictionary is not None:
		print 'Trying dictionary...'
		password = __checkPasswords(dictionary, zipFile)
	if len(charactersSet):
		if password is None:
			print 'Trying brute-force...'
			password = __checkPasswords(__generatePassword(charactersSet, minLength, maxLength), zipFile)
	if password is None:
		sys.stdout.write('\r\x1b[KSorry, not able to crack file. Try increasing the maxLength count.\n')
		sys.stdout.flush()
	else:
		sys.stdout.write('\r\x1b[K[+] Found password: ' + password + '\n')
		sys.stdout.flush()
	exit(0)

if '__main__' == __name__:
	main()
