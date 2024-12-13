#!/usr/bin/env python3

# This file is part of A Black Path Toward The Sun ("ABPTTS")

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

import os
import sys
import logging
import configparser
from zipfile import ZipFile
from shutil import copyfile

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

class ABPTTSVersion:
	@staticmethod
	def GetVersionString():
		return "2.0"
		
	@staticmethod
	def GetReleaseDateString():
		return "2024-11-30"

	@staticmethod
	def showBanner():
		print("---===[[[ A Black Path Toward The Sun ]]]===---")
		print("   --==[[       -  Client  -          ]]==--")
		print("            Ben Lincoln, NCC Group")
		print(f"            Version {ABPTTSVersion.GetVersionString()} - {ABPTTSVersion.GetReleaseDateString()}\n")
		
class ABPTTSConfiguration:
	def __init__(self):
		self.config = configparser.ConfigParser()
		self.config.optionxform = str
		self.randomizedValuePlaceholder = "|RANDOMIZE|"
	
	@staticmethod
	def MakeDir(newDir):
		if os.path.exists(newDir):
			logger.exception(f"Directory '{newDir}' already exists")
			return False

		try:
			os.mkdir(newDir)
		except Exception as e:
			logger.exception(f"Could not create a directory named '{newDir}' - {e}")
			return False
		
		return True

	@staticmethod
	def CopyFile(source, destination):
		try:
			copyfile(source, destination)
		except Exception as e:
			logger.exception(f"Could not copy '{source}' to '{destination}' - {e}")
			return False
		return True

	@staticmethod
	def ZipDir(sourceDirectory, outputFilePath):
		currentDir = os.getcwd()

		try:
			os.chdir(sourceDirectory)
			relroot = os.path.abspath(os.path.join(sourceDirectory))
			with ZipFile(outputFilePath, "w") as zip:
				for root, dirs, files in os.walk(sourceDirectory):
					# add directory (needed for empty dirs)
					# this is commented out because Tomcat 8 will reject WAR files with "./" in them.
					#zip.write(root, os.path.relpath(root, relroot))
					for file in files:
						filename = os.path.join(root, file)
						if os.path.isfile(filename): # regular files only
							arcname = os.path.join(os.path.relpath(root, relroot), file)
							zip.write(filename, arcname)
		except Exception as e:
			logger.exception(f"Could not create zip file '{outputFilePath}' from directory '{sourceDirectory}'  - {e}")
			return False
		
		os.chdir(currentDir)
		return True

	def ReplacePlaceholderValue(self, content, section, parameterName):
		placeholder = f"|PLACEHOLDER_{parameterName}|"
		return content.replace(placeholder, self.config[section][parameterName])
	
	def ReplaceValue(self, section, parameterName, newParameterValue):
		if section not in self.config.sections():
			logger.critical(f"Section {section} not in config file")
			sys.exit(1)
		elif not self.config.has_option(section, parameterName):
			logger.critical(f"Parameter {parameterName} not in config file")
			sys.exit(1)
		else:
			self.config.set(section, parameterName, newParameterValue)

	def GetValue(self, section, parameterName):
		if section not in self.config.sections():
			logger.critical(f"Section {section} not in config file")
			sys.exit(1)
		elif not self.config.has_option(section, parameterName):
			logger.critical(f"Parameter {parameterName} not in config file")
			sys.exit(1)
		else:
			return self.config.get(section, parameterName)

	def check_value(self, section, parameterName):
		if section not in self.config.sections():
			logger.critical(f"Section {section} not in config file")
			sys.exit(1)
		
		if not self.config.has_option(section, parameterName):
			logger.critical(f"Parameter {parameterName} not in config file")
			sys.exit(1)

	def get_boolean(self, section, parameterName):
		self.check_value(section, parameterName)		
		return self.config.getboolean(section, parameterName)

	def get_int(self, section, parameterName):
		self.check_value(section, parameterName)		
		return self.config.getint(section, parameterName)

	def get_float(self, section, parameterName):
		self.check_value(section, parameterName)		
		return self.config.getfloat(section, parameterName)

	def get_string(self, section, parameterName):
		self.check_value(section, parameterName)		
		return self.config.get(section, parameterName)

	def ReplaceIfRandomizationPlaceholder(self, parameterName, newParameterValue):
		for section in self.config.sections():
			if self.config.has_option(section, parameterName) and self.config.get(section, parameterName) == self.randomizedValuePlaceholder:
				self.config.set(section, parameterName, newParameterValue)

	def WriteClientFile(self, outputFilePath):
		try:
			with open(outputFilePath, 'w') as configfile:
				self.config.write(configfile)			
				logger.info(f"Created client configuration file '{outputFilePath}'")
		except Exception as e:
			logger.exception(f"Error writing to '{outputFilePath}' - {e}")

	def LoadParameters(self, parameterFileArray):
		try:
			self.config.read(parameterFileArray)
		except Exception as e:
			logger.exception(f"Could not read configuration files: {e}")
			sys.exit(1)		

	def ShowParameters(self):
		logger.setLevel(logging.DEBUG)
		logger.debug(f"HTTP Request Header Name for Access Key: {self.config["Authentication"]["headerNameKey"]}")
		logger.debug(f"Access Key: {self.config["Authentication"]["headerValueKey"]}")
		logger.debug(f"Encryption Key: {self.config["Encryption"]["encryptionKeyHex"]}")
		logger.debug(f"HTTP User-Agent Request Header Value: {self.config["Encryption"]["headerValueUserAgent"]}")
		logger.debug(f"Send Access Key As: {self.config["Encryption"]["accessKeyMode"]}")
		logger.debug(f"Request Body Parameter Name for Access Key: {self.config["Obfuscation"]["paramNameAccessKey"]}")
		logger.debug(f"Request Body Parameter Name for Operation Type: {self.config["Obfuscation"]["paramNameOperation"]}")
		logger.debug(f"Request Body Parameter Name for Destination Host: {self.config["Obfuscation"]["paramNameDestinationHost"]}")
		logger.debug(f"Request Body Parameter Name for Destination Port: {self.config["Obfuscation"]["paramNameDestinationPort"]}")
		logger.debug(f"Request Body Parameter Name for Connection ID: {self.config["Obfuscation"]["paramNameConnectionID"]}")
		logger.debug(f"Request Body Parameter Name for Tunneled Data: {self.config["Obfuscation"]["paramNameData"]}")
		logger.debug(f"Request Body Parameter Name for Plaintext Request Block: {self.config["Obfuscation"]["paramNamePlaintextBlock"]}")
		logger.debug(f"Request Body Parameter Name for Encrypted Request Block: {self.config["Obfuscation"]["paramNameEncryptedBlock"]}")
		logger.debug(f"Encapsulated Request Body Base64-Encoded Name/Value Separator: {self.config["Obfuscation"]["dataBlockNameValueSeparatorB64"]}")
		logger.debug(f"Encapsulated Request Body Base64-Encoded Parameter Separator: {self.config["Obfuscation"]["dataBlockParamSeparatorB64"]}")
		logger.debug(f"Request Body Parameter Value for Operation \"Open Connection\": {self.config["Obfuscation"]["opModeStringOpenConnection"]}")
		logger.debug(f"Request Body Parameter Value for Operation \"Send/Receive\": {self.config["Obfuscation"]["opModeStringSendReceive"]}")
		logger.debug(f"Request Body Parameter Value for Operation \"Close Connection\": {self.config["Obfuscation"]["opModeStringCloseConnection"]}")
		logger.debug(f"Response Code for \"Incorrect Access Key (Hide)\": {self.config["Obfuscation"]["responseStringHide"]}")
		logger.debug(f"Response Code for \"Connection Created\": {self.config["Obfuscation"]["responseStringConnectionCreated"]}")
		logger.debug(f"Response Code for \"Connection Closed\": {self.config["Obfuscation"]["responseStringConnectionClosed"]}")
		logger.debug(f"Response Prefix for Tunneled Data: {self.config["Obfuscation"]["responseStringData"]}")
		logger.debug(f"Response Code for \"No Data to Send\": {self.config["Obfuscation"]["responseStringNoData"]}")
		logger.debug(f"Response Code for \"Generic Error\": {self.config["Obfuscation"]["responseStringErrorGeneric"]}")
		logger.debug(f"Response Code for \"Invalid Request\": {self.config["Obfuscation"]["responseStringErrorInvalidRequest"]}")
		logger.debug(f"Response Code for \"Connection Not Found\": {self.config["Obfuscation"]["responseStringErrorConnectionNotFound"]}")
		logger.debug(f"Response Code for \"Failed to Open Connection\": {self.config["Obfuscation"]["responseStringErrorConnectionOpenFailed"]}")
		logger.debug(f"Response Code for \"Failed to Close Connection\": {self.config["Obfuscation"]["responseStringErrorConnectionCloseFailed"]}")
		logger.debug(f"Response Code for \"Failed to Send Data (Server-Side)\": {self.config["Obfuscation"]["responseStringErrorConnectionSendFailed"]}")
		logger.debug(f"Response Code for \"Failed to Receive Data (Server-Side)\": {self.config["Obfuscation"]["responseStringErrorConnectionReceiveFailed"]}")
		logger.debug(f"Response Code for \"Decryption Failure\": {self.config["Obfuscation"]["responseStringErrorDecryptFailed"]}")
		logger.debug(f"Response Code for \"Encryption Failure\": {self.config["Obfuscation"]["responseStringErrorEncryptFailed"]}")
		logger.debug(f"Response Code for \"Encryption Not Supported\": {self.config["Obfuscation"]["responseStringErrorEncryptionNotSupported"]}")
		logger.debug(f"Base64-Encoded Response Prefix: {self.config["Obfuscation"]["responseStringPrefixB64"]}")
		logger.debug(f"Base64-Encoded Response Suffix: {self.config["Obfuscation"]["responseStringSuffixB64"]}")
		logger.debug(f"Log File Path: {self.config["Logging"]["logFilePath"]}")
		logger.debug(f"Write to Log File: {self.config["Logging"]["writeToLog"]}")
		logger.debug(f"Write to Standard Output: {self.config["Logging"]["writeToStandardOut"]}")
		logger.debug(f"Output Raw Tunneled Data: {self.config["Logging"]["echoData"]}")
		logger.debug(f"Output HTTP Request/Response Bodies: {self.config["Logging"]["echoHTTPBody"]}")
		logger.debug(f"Output Debugging Messages: {self.config["Logging"]["echoDebugMessages"]}")
		logger.debug(f"Request/Response Iterations Between Tunneled Data Statistics Output: {self.config["Logging"]["statsUpdateIterations"]}")
		logger.debug(f"Application Name: {self.config["Output"]["fileGenerationAppNameShort"]}")
		logger.debug(f"Maximum Number of Bytes for Server to Return to Client Component With Each Send/Receive Operation: {self.config["Network.client"]["clientToServerBlockSize"]} bytes")
		logger.debug(f"Client Socket Buffer Size: {self.config["Network.client"]["clientSocketBufferSize"]} bytes")
		logger.debug(f"Automatically Adjust Client Socket Timeout: {self.config["Network.client"]["autoscaleClientSocketTimeout"]}")
		logger.debug(f"Block Size for Retransmission to Clients: {self.config["Network.client"]["clientBlockSizeLimitFromServer"]} bytes")	
		logger.debug(f"Sleep Time Between Client Socket Blocks: {self.config["Network.client"]["clientBlockTransmitSleepTime"]} seconds")
		logger.debug(f"Base Client Socket Timeout: {self.config["Network.client"]["clientSocketTimeoutBase"]} seconds")
		logger.debug(f"Client Socket Timeout Variation Range: {self.config["Network.client"]["clientSocketTimeoutVariation"]}")
		logger.debug(f"Client Socket Timeout Scaling Multiplier: {self.config["Network.client"]["clientSocketTimeoutScalingMultiplier"]}")
		logger.debug(f"Client Socket Maximum Timeout: {self.config["Network.client"]["clientSocketTimeoutMax"]}")
		logger.debug(f"Client Socket Minimum Timeout: {self.config["Network.client"]["clientSocketTimeoutMin"]}")
		logger.debug(f"Maximum Number of Bytes for Server to Return to Client Component With Each Send/Receive Operation: {self.config["Network.server"]["serverToClientBlockSize"]}")
		logger.debug(f"Maximum Unused Request/Response Iterations Before Abandoning Server-Side Socket: {self.config["Network.server"]["serverSocketMaxUnusedIterations"]}")
		logger.debug(f"Use IPv6 for Server-Side Client Sockets (See Documentation): {self.config["Network.server"]["useIPV6ClientSocketOnServer"]}")
		logger.debug(f"Server-Side Socket IO Timeout: {self.config["Network.server"]["serverSocketIOTimeout"]} milliseconds")
		logger.debug(f"Server-Side Socket Send Buffer Size: {self.config["Network.server"]["serverSocketSendBufferSize"]} bytes")
		logger.debug(f"Server-Side Socket Receive Buffer Size: {self.config["Network.server"]["serverSocketReceiveBufferSize"]} bytes")
		logger.setLevel(logging.INFO)

	def GetFileAsString(self, inputFilePath):
		result = ""

		try:
			with open(inputFilePath, 'r') as f:
				result = f.read()
		except Exception as e:
			logger.exception(f"Could not open the file '{inputFilePath}' - {e}")
			sys.exit(1)
			
		return result
		
	def GenerateServerFileFromTemplate(self, templateDirectory, templateFileName, outputDirectory):
		templateFilePath = os.path.join(templateDirectory, templateFileName)
		outputFilePath = os.path.join(outputDirectory, templateFileName)
		templateContent = self.GetFileAsString(templateFilePath)
		
		if not templateContent:
			logger.critical(f"The template file '{templateFilePath}' did not contain any content. No corresponding output file will be generated.")
			sys.exit(1)

		templateContent = self.ReplacePlaceholderValue(templateContent, "Network.server", "useIPV6ClientSocketOnServer")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Network.server", "serverToClientBlockSize")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Network.server", "serverSocketMaxUnusedIterations")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Network.server", "serverSocketIOTimeout")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Network.server", "serverSocketSendBufferSize")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Network.server", "serverSocketReceiveBufferSize")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Authentication", "headerNameKey")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Authentication", "headerValueKey")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Encryption", "encryptionKeyHex")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Encryption", "accessKeyMode")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameAccessKey")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameOperation")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameDestinationHost")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameDestinationPort")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameConnectionID")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameData")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNamePlaintextBlock")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "paramNameEncryptedBlock")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "dataBlockNameValueSeparatorB64")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "dataBlockParamSeparatorB64")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "opModeStringOpenConnection")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "opModeStringSendReceive")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "opModeStringCloseConnection")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringHide")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringConnectionCreated")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringConnectionClosed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringData")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringNoData")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorGeneric")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorInvalidRequest")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorConnectionNotFound")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorConnectionOpenFailed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorConnectionCloseFailed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorConnectionSendFailed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorConnectionReceiveFailed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorDecryptFailed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorEncryptFailed")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringErrorEncryptionNotSupported")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringPrefixB64")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Obfuscation", "responseStringSuffixB64")
		templateContent = self.ReplacePlaceholderValue(templateContent, "Output", "fileGenerationAppNameShort")

		try:
			with open(outputFilePath, 'w') as f:
				f.write(templateContent)
			logger.info(f"Created server file '{outputFilePath}'")
		except Exception as e:
			logger.exception(f"Output file '{outputFilePath}' could not be created - {e}")