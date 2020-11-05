from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os, random, struct, sys
from pbkdf2 import PBKDF2


passwd = "12345678901" #initialize with a random password
zero_bytes = bytes(16)
enc_label = b'enc'

class DummyLenAuthorizer(DummyAuthorizer):

    
    def validate_authentication(self, username, password, handler):
        try:
            if len(password) != 11:
                raise KeyError
            global passwd
            passwd = password
        except KeyError:
            raise AuthenticationFailed

class MyHandler(FTPHandler):

    def on_connect(self):
        print( "%s:%s connected".format(self.remote_ip, self.remote_port))

    def ftp_RETR(self, filepath):     # before sending file
        tmp_filepath = "/tmp/" + os.path.basename(filepath)
        os.system("cp "+ filepath.replace(" ","\\ ") + " " + tmp_filepath.replace(" ","\\ ")) # backup the encrypted  file
        decrypt(tmp_filepath, filepath)          # decrypt the received file at 'filepath'
        super(MyHandler, self).ftp_RETR(filepath)

    def on_file_sent(self, filepath):
        os.system("mv /tmp/"+ os.path.basename(filepath).replace(" ","\\ ")  + " " + filepath.replace(" ","\\ ")) # restore the encrypted  file
    
    def on_file_received(self, filepath):
        tmp_filepath = "/tmp/" + os.path.basename(filepath)
        os.system("cp "+ filepath.replace(" ","\\ ") + " " + tmp_filepath.replace(" ","\\ "))  # temp store the origial file
        encrypt(tmp_filepath, filepath)					                                # encrypt the received file at 'filepath'
        os.remove(tmp_filepath)		            	# remove the temp stored original file after encrypting

    def on_incomplete_file_received(self, filepath):
        # remove partially uploaded files
        os.remove(filepath)


def decrypt(in_filepath, out_filepath):						# function to decrypt files
    print("[!] Starting decryption....")

    aes_key = PBKDF2(passwd, zero_bytes, 16).read(16)     # AES symmetric key using user's password 				
 
    inFile = open(in_filepath,"rb")				# open the file to be decrypted as read-only
    chunksize=64*1024						# set the chunk size which is used as the block for block decryption

    enc_code = inFile.read(3)
    if enc_code == enc_label:
        origsize = struct.unpack('<Q', inFile.read(struct.calcsize('Q')))[0]	# calculate the original file size
        iv = inFile.read(16)								# extract next 16 bytes as the 16 bytes initialization vector 
        decryptor = AES.new(aes_key, AES.MODE_CBC, iv)		# create new AES Decryptor object

        with open(out_filepath, 'wb') as outfile:
            while True:
                chunk = inFile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))		# decrypt the file chunk by chunk using the created decryptor 
            
            outfile.truncate(origsize)						# truncate the decrypted file to the original size 
        
        print("[+] File was decrypted and saved at \""+out_filepath+"\"")
    inFile.close()
    return out_filepath
    
def encrypt(in_filepath, out_filepath):
    print("[!] Starting Encryption....")
    
    aes_key = PBKDF2(passwd, zero_bytes, 16).read(16)     # AES symmetric key using user's password 				
    
    outFile = open(out_filepath,"wb")					# Open a new file which will be our encrypted file

    iv = os.urandom(16)	# generate a 16 byte IV - Initialization vector which is used by AES algorithm with CBC to encrypt the first block of the file
    encryptor = AES.new(aes_key, AES.MODE_CBC, iv)	# create a new encryptor object
    filesize = os.path.getsize(in_filepath.replace(" ","\\ "))			# calculate the size of the original file which we are going to encrypt
    chunksize=64*1024								# initialize chunk size for block encryption
    
    with open(in_filepath, 'rb') as infile:
        outFile.write(enc_label)
        outFile.write(struct.pack('<Q', filesize)) 	# interpret the data string of the file as a packed binary data. This is needed at the destination to truncate the file to its original size.
        outFile.write(iv)							# write the generated IV to the file. IV is needed by the destination to decrypt only the first block of encrypted data
        
        while True:
            chunk = infile.read(chunksize)			# read a chunk of data from the file
            if len(chunk) == 0:						
                break								# if the chunk is empty, obviously file has been completed reading. So break the reading operation
            elif len(chunk) % 16 != 0:
                chunk += zero_bytes[0:(16 - len(chunk) % 16)]	# if the chunk's size is not a multiple of 16 bytes, it needs to be padded so that it can be block encrypted. So add spaces as paddinig
            outFile.write(encryptor.encrypt(chunk))		# encrypt the chunk and write the encrypted chunk to the file
    
    outFile.close()
    print("[+] Encryption successful!")
    return out_filepath			# return the encrypted file's path to the caller (client)


def main():
    authorizer = DummyLenAuthorizer()
    authorizer.add_user(sys.argv[1], '', homedir=sys.argv[2], perm='elradfmwMT')
    #authorizer.add_anonymous(homedir='.')

    handler = MyHandler
    handler.authorizer = authorizer
    handler.permit_foreign_addresses = True
    server = FTPServer(('', 9921), handler)
    server.serve_forever()

if __name__ == "__main__":
    main()