import sys
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

'''
	Class to simulate a SSLv3 protocol
'''
class SSLv3:
	def __init__(self, block_size=16, key_length=16):
		# Initialize a SSL connection with a random key
		# and default block size = 16
		self.key = Random.get_random_bytes(key_length)
		self.block_size = block_size
		self.aes = AES.new(self.key)

	# Function to add padding to the message
	def pad(self, msg):
		x = len(msg) % self.block_size
		pad_len = self.block_size - x - 1
		return msg + Random.get_random_bytes(pad_len) + bytes([pad_len])

	# returns a list of message blocks each of size block_size
	def convert_to_blocks(self, msg):
		return [msg[i: i + self.block_size] for i in range(0, len(msg), self.block_size)]

	# performs xor for bytes
	def xor(self, b1, b2):
		res = bytearray()
		for b1, b2 in zip(b1, b2):
			res.append(b1 ^ b2)
		return bytes(res)

	# encrypts a block using block cipher AES
	def encrypt_block(self, msg):
		return self.aes.encrypt(msg)

	# decrypts a block using block cipher AES
	def decrypt_block(self, msg):
		return self.aes.decrypt(msg)

	# encrypts the plaintext using block cipher AES in CBC mode
	def encrypt_CBC(self, msg):
		cipher_text = []
		iv = Random.get_random_bytes(self.block_size)
		self.iv = iv
		blocks = self.convert_to_blocks(msg)
		for block in blocks:
			temp = self.xor(iv, block)
			ct = self.encrypt_block(temp)
			cipher_text.append(ct)
			iv = ct

		return b''.join(cipher_text)

	# decrypts the plaintext using block cipher AES in CBC mode
	def decrypt_CBC(self, msg):
		plain_text = []
		blocks = self.convert_to_blocks(msg)
		blocks.insert(0, self.iv)
		for i in range(len(blocks)-1, 0, -1):
			block = blocks[i]
			temp = self.decrypt_block(block)
			iv = blocks[i - 1]
			pt = self.xor(iv, temp)
			plain_text.append(pt)

		return b''.join(plain_text[::-1])

	'''
		1. Takes a message as input
		2. Calculate MAC of the plaintext using MD5 hash function
		3. Add this MAC to the plaintext
		4. Add padding to the message
		5. return the encrypted message using CBC
	'''
	def encrypt(self, msg):
		mac = hashlib.md5(msg).digest()
		msg += mac
		msg = self.pad(msg)
		return self.encrypt_CBC(msg)

	'''
		1. Takes a ciphertext as input
		2. Decrypt the message using CBC
		3. If the last byte does not belong in 0..15, reject the request.
		3. Get MAC from the cipher text
		4. Calculate MAC from the plaintext and compare it with MAC from the cipher text.
		5. If MAC matches, return the decrypted message else reject
	'''
	def decrypt(self, msg):
		msg = self.decrypt_CBC(msg)
		if (msg[-1] > 15 or msg[-1] < 0):
			return False, None
		pad_len = msg[-1]
		msg = msg[:-(pad_len + 1)]
		plain_text, mac = msg[:-16], msg[-16:]
		if (hashlib.md5(plain_text).digest() != mac):
			return False, None

		return True, plain_text

'''
	Class to simulate POODLE attack
'''
class Poodle:
	def __init__(self, msg, block_size=16):
		self.msg = msg
		self.block_size = block_size

	''' 
		Function to simulate sending of requests from the client to the server. It assumes the attacker have full control over the path and body of the message
		1. First add HTTP header before the message
		2. Add the path
		3. Append the message (length changed according to attacker)
		4. return the encrypted request using the SSLv3 protocol
	'''
	def send_from_client(self, path=b'', strip_bytes=0):
		self.session = SSLv3()
		header = b'HTTP Req Path:/'
		msg = header + path + b' ' + self.msg[:len(self.msg)-strip_bytes]
		return self.session.encrypt(msg)

	'''
		Function to simulate server response on receiving the request from the client. It decrypts the request and send accept/reject response to client.
	'''
	def server_response(self, cipher_text):
		response, plain_text = self.session.decrypt(cipher_text)
		return response

	'''
		Function to decrypt one byte using the POODLE attack. It takes the modified path as the input and block number and byte number to decrypt.
		1. Intercepts/Gets a ciphertext from the client.
		2. Modify the cipher text such that the target block is the last block
		3. Send the modified request to the server.
		4. If rejected, repeat the above process.
		4. If accepted, decrypt the last byte
	'''
	def break_byte(self, path, block_no, j=0):
		print ('[@] Decrypting Byte #' + str(self.block_size - j - 1))
		print ()
		flag = False
		i = 0
		mod_cipher = ''
		while not flag:
			cipher_text = self.send_from_client(path=path, strip_bytes=j)
			blocks = self.session.convert_to_blocks(cipher_text)
			mod_cipher = cipher_text[:-self.block_size] + blocks[block_no]
			flag = self.server_response(mod_cipher)
			i += 1
		byte = 15 ^ mod_cipher[-self.block_size-1] ^ mod_cipher[self.block_size*block_no - 1]

		print ('Decrypted in ' + str(i) + ' tries')
		print ('Decrypted Byte: ' + str(byte))
		print ()

		return bytes([byte])

	'''
		Function to decrypt all the bytes in a block using break_byte function. It shifts the ciphertext by one byte at a time to decrypt the entire.
	'''
	def break_block(self, path, block_no):
		print ('[@] Decrypting Block #' + str(block_no))
		print ()
		block = b''
		limit = self.block_size - self.path_len if block_no == 1 else self.block_size;

		for i in range(limit):
			byte = self.break_byte(path + b'a' * i, block_no, i)
			block = byte + block

		print ('[@] Decrypted Block #' + str(block_no) + ': ' + str(block))
		print ()

		return block

	'''
		Performs the poodle attack
		1. Keep adding one byte in the path till the length of cipher text changes.
		2. When the length of cipher text changes, it means that the last block is full padding block. Now we decrypt all block using above function.
		3. We concatenate all the decrypted blocks to the plain text.
	'''
	def poodle_attack(self, cipher_text):
		cipher_text_len = len(cipher_text)
		path = b''
		while cipher_text_len == len(cipher_text):
			path += b'A'
			cipher_text = self.send_from_client(path)

		print ('[@] Cipher Text where last block is full padding block')
		print (cipher_text)
		print ()

		self.path_len = len(path)

		blocks = self.session.convert_to_blocks(cipher_text)

		plain_text = b''
		for i in range(1, len(blocks) - 2):
			plain_text += self.break_block(path, i)

		return plain_text.decode('utf-8')

if __name__ == '__main__':
	sslv3 = SSLv3()
	msg = bytes('This is Cryptography Assignment 3', 'utf-8')

	if len(sys.argv) == 2:
		msg = bytes(sys.argv[1], 'utf-8')

	poodle = Poodle(msg)
	print ('[@] Original Message:')
	print (msg.decode('utf-8'))
	print ()

	cipher_text = poodle.send_from_client()
	print ('[@] Original Cipher Text:')
	print (cipher_text)
	print ()

	plain_text = poodle.poodle_attack(cipher_text)

	print ('[@] Decrypted Plain Text')
	print (plain_text)