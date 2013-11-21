# zipPasswordCracker
# version 0.8

# Simple encrypted zip file password dictionary and bruce-force cracker
# Original script from https://gist.github.com/23ars/6613420

import zipfile
from argparse import ArgumentParser
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

def __generatePasswords(words, minLength, maxlength):
    return (''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(words, repeat=i)
        for i in range(minLength, maxlength + 1)))

def __checkPasswords(passwordList, zipFile):
	pool = ThreadPool(processes=16)
	stop = False
	global quiet
	while stop is False:
		for password in passwordList:
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
	parser = ArgumentParser()
	parser.add_argument('-f', '--file', dest='zipFile', metavar='<filename>', required=True, type=str,
		help='path to zip file to attack')
	parser.add_argument('-v', '--version', action='version', version='v0.8')
	parser.add_argument('-d', '--dictionary-file', dest='dictionaryFile', metavar='<filename>',
		type=str, help='path to password dictionary file for dictionary attacks (one password per line)')
	parser.add_argument('-c', '--concat-password-dictionary', dest='concatDictionary', action='store_true',
		help='try dictionary words concatinated with each other - only valid with --dictionary-file (-d) option')
	parser.add_argument('-s', '--start-length', dest='minLength', metavar='N', default=1, type=int,
		help='minimum length for brute-force and concatinated dictionary attacks - defaults to 1')
	parser.add_argument('-e', '--end-length', dest='maxLength', metavar='N', default=6, type=int,
		help='maximum length for brute-force and concatinated dictionary attacks - defaults to 6')
	parser.add_argument('-n', '--no-brute-force', dest='bruteForce', action='store_false',
		help='do not brute force, only use dictionary - --dictionary-file (-d) option must be used')
	parser.add_argument('--no-lower-case', dest='lowerCase', action='store_false',
		help='do not use lower-case letters in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--no-upper-case', dest='upperCase', action='store_false',
		help='do not use upper-case letters in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--no-numbers', dest='numbers', action='store_false',
		help='do not use numbers (0-9) in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--no-punctuation', dest='punctuation', action='store_false',
		help='do not use punctuation in brute-force attacks - ignored if --use-character-set is specified')
	parser.add_argument('--use-character-set', dest='charactersSet', metavar='<string of chacters>', type=list,
		help='use characters from supplied set instead of built-in set - above character set options are ignored.')
	parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
		help='do not print passwords to stdout')
	args = parser.parse_args()

	global quiet
	quiet = args.quiet
	dictionary = None
	concatDictionary = args.concatDictionary
	zipFile = zipfile.ZipFile(args.zipFile)
	minLength = args.minLength
	maxLength = args.maxLength
	bruteForce = args.bruteForce
	lowerCase = args.lowerCase
	upperCase = args.upperCase
	numbers = args.numbers
	punctuation = args.punctuation
	charactersSet = args.charactersSet

	if maxLength < minLength:
		__exit('--end-length can not be lower than --start-length.')

	if concatDictionary and args.dictionaryFile is None:
		__exit('--concat-password-dictionary can only be used with the --dictionary-file (-d) option')

	if args.dictionaryFile is not None:
		file = open(args.dictionaryFile, 'r')
		dictionary = []
		for line in file.readlines():
			dictionary.append(line.strip('\n\r'))

	if charactersSet is None: # if character set was supplied on command line, skip this
		charactersSet = ''
		if lowerCase:
			charactersSet = charactersSet + string.ascii_lowercase
		if upperCase:
			charactersSet = charactersSet + string.ascii_uppercase
		if numbers:
			charactersSet = charactersSet + string.digits
		if punctuation:
			charactersSet = charactersSet + string.punctuation

	if dictionary is None and charactersSet is None:
		__exit('Nothing to do as no dictionary was specified and all brute-forcing options are disabled.')

	password = None
	if dictionary is not None:
		print 'Trying dictionary words...'
		password = __checkPasswords(dictionary, zipFile) # A *lot* of time gets spent here
		if concatDictionary:
			__output('') # clear line from previous password check
			print 'Trying concatinated dictionary words...'
			passwords = __generatePasswords(dictionary, minLength, maxLength)
			password = __checkPasswords(passwords, zipFile) # A *lot* of time gets spent here
	if bruteForce and charactersSet is not None and password is None:
		__output('') # clear line from previous password check
		print 'Trying brute-force...'
		passwords = __generatePasswords(charactersSet, minLength, maxLength)
		password = __checkPasswords(passwords, zipFile) # A *lot* of time gets spent here
	if password:
		__output('[+] Found password: ' + password + '\n')
	else:
		__output('Sorry, not able to crack file with specified settings.\n')

	exit(0)

if '__main__' == __name__:
	main()
