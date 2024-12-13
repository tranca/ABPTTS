#!/usr/bin/env python3

#	This file is part of A Black Path Toward The Sun ("ABPTTS")

# Copyright 2024 NCC Group

# A Black Path Toward The Sun ("ABPTTS") is free software: you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as published by
# the Free Software Foundation.

# A Black Path Toward The Sun ("ABPTTS") is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with A Black Path Toward The Sun ("ABPTTS") (in the file license.txt).
# If not, see <http://www.gnu.org/licenses/>.

# Configuration file/server component package generator for A Black Path Toward The Sun

import inspect
import logging
import base64
import random
import sys
import os
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter,  RawDescriptionHelpFormatter

from libabptts import ABPTTSConfiguration, ABPTTSVersion

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

conf = ABPTTSConfiguration()

serverFilenameJSP = 'abptts.jsp'
serverFilenameASPX = 'abptts.aspx'

serverFileTemplates = []
serverFileTemplates.append(serverFilenameJSP)
serverFileTemplates.append(serverFilenameASPX)

wrapperTemplateFileContentPlaceholder = "|ABPTTS_RESPONSE_CONTENT|"

# minimum number of entries in the wordlist used for certain random name/value generation
wordlistMinCount = 10

# minimum number of bytes to generate for the authentication key
authKeyMinLength = 16

# maximum number of bytes to generate for the authentication key
authKeyMaxLength = 32

# number of bytes to generate for the encryption key
encryptionKeyLength = 16
	
def GetRandomListEntry(sourceList):
	entryNum = random.randint(0, len(sourceList) - 1)
	return sourceList[entryNum].strip()

def CapitalizeFirst(inputString):
	return inputString[0:1].upper() + inputString[1:].lower()
	
def RandomlyModifyCaps(inputString):
	mode = random.randint(0, 5)
	if mode < 2:
		return inputString
	if mode == 2:
		return CapitalizeFirst(inputString)
	if mode == 3:
		return inputString.upper()
	if mode == 4:
		return inputString.lower()
	return inputString
	
def RandomlyCapitalizeFirst(inputString):
	mode = random.randint(0, 10)
	if mode < 5:
		return inputString
	return CapitalizeFirst(inputString)
	
if __name__=='__main__':
	ABPTTSVersion.showBanner()

	basePath = os.path.abspath(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))))
	dataFilePath = os.path.join(basePath, 'data')
	templateFilePath = os.path.join(basePath, 'template')
	userAgentListPath = os.path.join(dataFilePath, 'user-agents.txt')

	parser = ArgumentParser(prog='ABPTTS', 
    	formatter_class=ArgumentDefaultsHelpFormatter,
		usage='%(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -o BASE_OUTPUT_DIRECTORY [--output-filename OUTPUT_CONFIG_FILE] [-w OUTPUT_WRAPPER_TEMLATE_FILE] [--ignore-defaults] [--wordlist WORDLIST_FILE] [--debug]',
		description='This utility generates a configuration file and matching server-side code (JSP, etc.) to be used with the ABPTTS client component.',
		epilog='Example: %(prog)s -c CONFIG_FILE_1 -o /home/blincoln/abptts/config/10.87.134.12 \
			Example: %(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -o /home/blincoln/abptts/config/supervulnerable.goingtogethacked.internet \
			Data from configuration files is applied in sequential order, to allow partial customization files to be overlayed on top of more complete base files. \
			IE if the same parameter is defined twice in the same file, the later value takes precedence, and if it is defined in two files, the value in whichever file is specified last on the command line takes precedence.')
	parser.add_argument('-c', help='specifies configuration files', default=[], action='append', dest='config_files')
	parser.add_argument('-o', help='specifies an output directory for the configuration', required=True, dest='output_dir')
	parser.add_argument('--output-filename', help='specifies an alternate output filename for the configuration', default='config.txt', dest='output_file')
	parser.add_argument('-t', help='specifies a template file to use for generating the response wrapper prefix/suffix - see the documentation for details', default=os.path.join(templateFilePath, 'response_wrapper.html'), dest='template_file')
	parser.add_argument('--ignore-defaults', help='prevents loading the default configuration as the base. For example, use this mode to merge two or more custom configuration overlay files without including options not explicitly defined in them. IMPORTANT: this will disable generation of server-side files (because if the defaults are not available, it would be very complicated to determine if all necessary parameters have been specified).', action='store_true')
	parser.add_argument('--wordlist', help='allows specification of a custom wordlist file (for random parameter name/value generation) instead of the default.', default=os.path.join(dataFilePath, 'american-english-lowercase-4-64.txt'), dest='wordlist_file',)
	parser.add_argument('--debug', help='enables verbose output.', action='store_true')

	args = parser.parse_args()
	
	baseOutputDirectory = os.path.abspath(args.output_dir)

	if not args.ignore_defaults:
		args.config_files.append(os.path.join(dataFilePath, 'settings-default.txt'))
		
	if not args.config_files:
		logger.critical("You have specified the --ignore-defaults flag, but not explicitly specified any configuration files. At least one configuration file must be specified.")
		sys.exit(1)
			
	conf.LoadParameters(args.config_files)
	
	if os.path.exists(baseOutputDirectory):
		if not os.path.isdir(baseOutputDirectory):
			logger.exception(f"A file named '{baseOutputDirectory}' already exists, so that location cannot be used as an output directory. Delete/rename the existing file, or choose a new output directory.")
			sys.exit(1)
	else:
		conf.MakeDir(baseOutputDirectory)
	
	outputConfigFilePath = os.path.join(baseOutputDirectory, args.output_file)
	
	logger.info(f"Output files will be created in '{baseOutputDirectory}'")
	logger.info(f"Client-side configuration file will be written as '{outputConfigFilePath}'")
	
	if os.path.exists(args.wordlist_file):
		logger.info(f"Using '{args.wordlist_file}' as a wordlist file")
	else:
		logger.critical(f"Could not find the wordlist file '{args.wordlist_file}'")
		sys.exit(1)
		
	wl = conf.GetFileAsString(args.wordlist_file)
	if not wl:
		logger.critical(f"No content obtained from wordlist file '{args.wordlist_file}'")
		sys.exit(1)
	wordList = wl.splitlines()
	
	wc = len(wordList)
	if len(wordList) < wordlistMinCount:
		logger.critical(f"The wordlist file '{args.wordlist_file}' only contained {wc} entries, but at least {wordlistMinCount} are required.")
		sys.exit(1)
	
	ual = conf.GetFileAsString(userAgentListPath)
	if not ual:
		logger.critical(f"No content obtained from user-agent list file {userAgentListPath}")
		sys.exit(1)
	userAgentList = ual.splitlines()

	wrapperPrefix = ""
	wrapperSuffix = ""

	if os.path.exists(args.template_file):
		try:
			wrapperTemplateFileContents = conf.GetFileAsString(args.template_file)
			wtfcArray = wrapperTemplateFileContents.split(wrapperTemplateFileContentPlaceholder)
			if len(wtfcArray) > 1:
				wrapperPrefix = wtfcArray[0]
				wrapperSuffix = wtfcArray[1]
		except Exception as e:
			logger.exception(f"Could not process response wrapper template file {baseOutputDirectory} - {e}")
			sys.exit(1)
	else:
		logger.fatal(f"File '{args.template_file}' doesn't exist.")
		sys.exit(1)

	if wrapperPrefix != "":
		conf.ReplaceValue("Obfuscation", "responseStringPrefixB64", base64.b64encode(wrapperPrefix.encode()).decode())
	if wrapperSuffix != "":
		conf.ReplaceValue("Obfuscation", "responseStringSuffixB64", base64.b64encode(wrapperSuffix.encode()).decode())

	separators = [ '', '.', '_', '-', '@', '#', '$', '&', '|', '/' ]
	randomStrings = []
	randomStringsWithSeparators = []
	checkStrings = []
	while len(randomStrings) < 16:
		word1 = RandomlyCapitalizeFirst(GetRandomListEntry(wordList))
		word2 = CapitalizeFirst(GetRandomListEntry(wordList))
		newString = f"{word1}{word2}"
		if newString.lower() not in checkStrings:
			randomStrings.append(newString)
			checkStrings.append(newString.lower())
			
	while len(randomStringsWithSeparators) < 16:
		word1 = os.urandom(random.randint(1, 36)).hex()
		word2 = os.urandom(random.randint(1, 36)).hex()
		newString = f"{word1}{GetRandomListEntry(separators)}{word2}"
		if newString.lower() not in checkStrings:
			randomStringsWithSeparators.append(newString)
			checkStrings.append(newString.lower())
	
	conf.ReplaceIfRandomizationPlaceholder('headerValueUserAgent', GetRandomListEntry(userAgentList))
	conf.ReplaceIfRandomizationPlaceholder('headerNameKey', f"x-{GetRandomListEntry(wordList).lower()}-{GetRandomListEntry(wordList).lower()}-{GetRandomListEntry(wordList).lower()}")
	authKeyLength = random.randint(authKeyMinLength, authKeyMaxLength)	
	conf.ReplaceIfRandomizationPlaceholder('headerValueKey', base64.b64encode(os.urandom(authKeyLength)).decode())	
	conf.ReplaceIfRandomizationPlaceholder('encryptionKeyHex', os.urandom(encryptionKeyLength).hex())
	
	conf.ReplaceIfRandomizationPlaceholder('paramNameAccessKey', randomStrings[11])
	conf.ReplaceIfRandomizationPlaceholder('paramNameOperation', randomStrings[0])
	conf.ReplaceIfRandomizationPlaceholder('paramNameDestinationHost', randomStrings[1])
	conf.ReplaceIfRandomizationPlaceholder('paramNameDestinationPort', randomStrings[2])
	conf.ReplaceIfRandomizationPlaceholder('paramNameConnectionID', randomStrings[3])
	conf.ReplaceIfRandomizationPlaceholder('paramNameData', randomStrings[4])
	conf.ReplaceIfRandomizationPlaceholder('paramNamePlaintextBlock', randomStrings[5])
	conf.ReplaceIfRandomizationPlaceholder('paramNameEncryptedBlock', randomStrings[6])
	conf.ReplaceIfRandomizationPlaceholder('opModeStringOpenConnection', randomStrings[7])
	conf.ReplaceIfRandomizationPlaceholder('opModeStringSendReceive', randomStrings[8])
	conf.ReplaceIfRandomizationPlaceholder('opModeStringCloseConnection', randomStrings[9])
	conf.ReplaceIfRandomizationPlaceholder('fileGenerationAppNameShort', randomStrings[10])
	
	conf.ReplaceIfRandomizationPlaceholder('responseStringHide', randomStringsWithSeparators[0])
	conf.ReplaceIfRandomizationPlaceholder('responseStringConnectionCreated', randomStringsWithSeparators[1])
	conf.ReplaceIfRandomizationPlaceholder('responseStringConnectionClosed', randomStringsWithSeparators[2])
	conf.ReplaceIfRandomizationPlaceholder('responseStringData', randomStringsWithSeparators[3])
	conf.ReplaceIfRandomizationPlaceholder('responseStringNoData', randomStringsWithSeparators[4])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorGeneric', randomStringsWithSeparators[5])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorInvalidRequest', randomStringsWithSeparators[6])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorConnectionNotFound', randomStringsWithSeparators[7])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorConnectionOpenFailed', randomStringsWithSeparators[8])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorConnectionCloseFailed', randomStringsWithSeparators[9])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorConnectionSendFailed', randomStringsWithSeparators[10])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorConnectionReceiveFailed', randomStringsWithSeparators[11])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorDecryptFailed', randomStringsWithSeparators[12])	
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorEncryptFailed', randomStringsWithSeparators[13])
	conf.ReplaceIfRandomizationPlaceholder('responseStringErrorEncryptionNotSupported', randomStringsWithSeparators[14])
	
	blockSeparatorChars = []
	# use entire ASCII non-printable range except for null bytes
	for i in range(1, 32):
		blockSeparatorChars.append(chr(i))

	bscl = len(blockSeparatorChars) - 1
	nvsIndex = random.randint(0, bscl)
	psIndex = random.randint(0, bscl)

	while nvsIndex == psIndex:
		psIndex = random.randint(0, bscl)
		
	conf.ReplaceIfRandomizationPlaceholder('dataBlockNameValueSeparatorB64', base64.b64encode(blockSeparatorChars[nvsIndex].encode()).decode())
	conf.ReplaceIfRandomizationPlaceholder('dataBlockParamSeparatorB64', base64.b64encode(blockSeparatorChars[psIndex].encode()).decode())
	
	if args.debug:
		logger.setLevel(logging.DEBUG)
		logger.debug("Building ABPTTS configuration with the following values:")
		conf.ShowParameters()
		logger.setLevel(logging.INFO)
	
	conf.WriteClientFile(outputConfigFilePath)
	
	if args.ignore_defaults:
		logger.info("The --ignore-defaults flag was specified, so no server-side files will be generated")
	else:
		# reload the configuration with the generated content
		args.config_files.append(outputConfigFilePath)
		conf.LoadParameters(args.config_files)
		
		for sft in serverFileTemplates:
			conf.GenerateServerFileFromTemplate(templateFilePath, sft, baseOutputDirectory)
			
		# auto-generate WAR file based on the generated JSP
		createWAR = True
		warRelativePath = 'war'	
		
		warInputDirectory = os.path.abspath(os.path.join(templateFilePath, warRelativePath))
		warWEBINFInputDirectory = os.path.join(warInputDirectory, 'WEB-INF')
		warMETAINFInputDirectory = os.path.join(warInputDirectory, 'META-INF')
		warJSPInputPath = os.path.join(baseOutputDirectory, serverFilenameJSP)
		
		warOutputDirectory = os.path.abspath(os.path.join(baseOutputDirectory, warRelativePath))
		warWEBINFOutputDirectory = os.path.join(warOutputDirectory, 'WEB-INF')
		warMETAINFOutputDirectory = os.path.join(warOutputDirectory, 'META-INF')		
		warJSPOutputPath = os.path.join(warOutputDirectory, f"{conf.GetValue("Output", "fileGenerationAppNameShort")}.war")		
		warOutputPath = os.path.join(baseOutputDirectory, f"{conf.GetValue("Output", "fileGenerationAppNameShort")}.war")

		dirCreated = conf.MakeDir(warOutputDirectory)
		if not dirCreated:
			createWAR = False

		if createWAR:
			dirCreated = conf.MakeDir(warWEBINFOutputDirectory)
			if not dirCreated:
				createWAR = False
		if createWAR:
			dirCreated = conf.MakeDir(warMETAINFOutputDirectory)
			if not dirCreated:
				createWAR = False
		if createWAR:
			conf.GenerateServerFileFromTemplate(warWEBINFInputDirectory, 'web.xml', warWEBINFOutputDirectory)
			conf.GenerateServerFileFromTemplate(warMETAINFInputDirectory, 'MANIFEST.MF', warMETAINFOutputDirectory)
			createWAR = conf.CopyFile(warJSPInputPath, warJSPOutputPath)
		if createWAR:
			createWAR = conf.ZipDir(warOutputDirectory, warOutputPath)
		if createWAR:
			logger.info('Prebuilt JSP WAR file: %s' % (warOutputPath))
			logger.info('Unpacked WAR file contents: %s' % (warOutputDirectory))