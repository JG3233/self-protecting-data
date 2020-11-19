import os, random, struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import getpass
import time
import pwd
import _thread
import hmac
import hashlib

try:
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    from Crypto.Util.py3compat import bchr, bord
    def pad(data_to_pad, block_size):
        padding_len = block_size-len(data_to_pad)%block_size
        padding = bchr(padding_len)*padding_len
        return data_to_pad + padding
    def unpad(padded_data, block_size):
        pdata_len = len(padded_data)
        if pdata_len % block_size:
            raise ValueError("Input data is not padded")
        padding_len = bord(padded_data[-1])
        if padding_len<1 or padding_len>min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
            raise ValueError("PKCS#7 padding is incorrect.")
        return padded_data[:-padding_len]
def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.enc'
    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            pos = 0
            while pos < filesize:
                chunk = infile.read(chunksize)
                pos += len(chunk)
                if pos == filesize:
                    chunk = pad(chunk, AES.block_size)
                outfile.write(encryptor.encrypt(chunk))
    print("Encryption Finished!")

def decrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.dec'
    with open(in_filename, 'rb') as infile:
        filesize = struct.unpack('<Q', infile.read(8))[0]
        iv = infile.read(16)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            encrypted_filesize = os.path.getsize(in_filename)
            pos = 8 + 16 # the filesize and IV.
            while pos < encrypted_filesize:
                chunk = infile.read(chunksize)
                pos += len(chunk)
                chunk = encryptor.decrypt(chunk)
                if pos == encrypted_filesize:
                    chunk = unpad(chunk, AES.block_size)
                outfile.write(chunk) 
    print("Decryption Finished!")


def cal_hmac(key, file_path):

    file_input = open(file_path, 'r')
    file_content = file_input.read()

    file = open(file_path, 'a+')
    try:

        mac = hmac.new(key, bytes(file_content,encoding = "utf-8") , hashlib.sha256)

        file.write(mac.hexdigest() + '\n')
    finally:
        file_input.close()
        file.close()


def data_op_monitor(delay):
    while(True):
        time.sleep(5)
        os.system('ps -A | grep cp >> op_monitor.txt')


def data_op_record(op):
    with open('op_trace.txt', 'a+') as outfile:
        outfile.write( pwd.getpwuid(os.getuid())[0] + ' ' + op + ' ' + str(time.asctime(time.localtime(time.time()))) + "\n")
        outfile.flush()


if __name__=='__main__':


    os.system('rm -rf ./op_trace.txt')
    os.system('rm -rf ./op_monitor.txt')

    passwd = getpass.getpass("input your key:\n")
    hash_pwd = SHA256.new()
    hash_pwd.update(bytes(passwd, encoding = "utf-8"))
    # print(hash_pwd.hexdigest())
    _thread.start_new_thread(data_op_monitor,(5,))
    while True:
        op = input("Choose your operation:\n1. encrypt a file\n2. decrypt a file\n3. remove a file\n4. dumplog\n5. exit\n")
        if op == '5':
            cal_hmac(hash_pwd.hexdigest().encode('utf-8'), 'op_trace.txt')
            cal_hmac(hash_pwd.hexdigest().encode('utf-8'), 'op_monitor.txt')
            break
        elif op == '1':
            input_path = input("Input plaintext file path:\n")
            output_path = input("Input encrypted file path\n")
            data_op_record('encrypt')
            encrypt_file(hash_pwd.hexdigest()[0:32].encode('utf-8'),input_path,output_path)
        elif op == '2':
            input_path = input("Input encrypted file path:\n")
            output_path = input("Input plaintext file path\n")
            data_op_record('decrypt')
            decrypt_file(hash_pwd.hexdigest()[0:32].encode('utf-8'),input_path,output_path)
        elif op == '3':
            input_path = input("Input path of the file you want to delete:\n")
            data_op_record('delete')
            os.system("rm -rf " + input_path)
            print("Delete Finished!\n")
        elif op == '4':
            print("=================data operation records================\n");
            os.system("cat ./op_trace.txt")
            print("=================global data operation records================\n");
            os.system("cat ./op_monitor.txt")
           
