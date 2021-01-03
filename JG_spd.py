import os, random, struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from geopy.geocoders import Nominatim
from geopy.distance import geodesic
import getpass
import time
import pwd
import _thread
import hmac
import hashlib
import geocoder

# File supplied to and adapted by Jacob Gilhaus for a final
# project in CSE433 at Washington University in St. Louis with
# Dr. Ning Zhang and Dr. Steve Cole, forked from J1nwenWang

try:
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    from Crypto.Util.py3compat import bchr, bord
    
    # padding function as equivalent of failed pad import
    def pad(data_to_pad, block_size):
        padding_len = block_size-len(data_to_pad)%block_size
        padding = bchr(padding_len)*padding_len
        return data_to_pad + padding
    
    # unpadding function as equivalent of failed unpad import
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

# define a function to encrypt the files according to the key supplied
def encrypt_file(key, in_filename, out_filename=None, file_anchor=None, allowed_distance=50, chunksize=64*1024):    
    # just add .enc if no new filename supplied
    if not out_filename:
        out_filename = in_filename + '.enc'

    if not file_anchor:
        file_anchor = '3312 Eagle Crest Rd Bloomington, Illinois'

    # get some needed values to encrypt the file
    # use AES in CBC mode with random iv and setup longitude and latitude
    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    print(file_anchor)
    file_anchor = geolocator.geocode(file_anchor)
    print(file_anchor)
    anchlat = float(file_anchor.latitude)
    anchlng = float(file_anchor.longitude)
    
    # must be 8 characters to maintain offset
    if anchlat < 0:
        if anchlat > -100:
            anchlat = float("%07.4f"%anchlat)
        else:
            anchlat = float("%07.3f"%anchlat)
    else:
        if anchlat < 100:
            anchlat = float("%07.5f"%anchlat)
        else:
            anchlat = float("%07.4f"%anchlat)

    
    if anchlng < 0:
        if anchlng > -100:
            anchlng = float("%07.4f"%anchlng)
        else:
            anchlng = float("%07.3f"%anchlng)
    else:
        if anchlng < 100:
            anchlng = float("%07.5f"%anchlng)
        else:
            anchlng = float("%07.4f"%anchlng)

    print(anchlng, anchlat)
    print(len(struct.pack('<f', anchlng)), len(struct.pack('<f', anchlat)))

    # write the encrypted file with filesize and iv first
    # encrypt chunks at a time at the end of the write loop
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            # TODO move the lat and lng to be encrypted?
            outfile.write(struct.pack('<f', anchlng))
            outfile.write(struct.pack('<f', anchlat))
            pos = 0
            while pos < filesize:
                chunk = infile.read(chunksize)
                pos += len(chunk)
                if pos == filesize:
                    chunk = pad(chunk, AES.block_size)
                outfile.write(encryptor.encrypt(chunk))

    print("Encryption Finished!")

# reverse the encrypt function, requires correct key or may throw error
def decrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    # check location parameters before allowing access
    # TODO update dummy values here!
    latdist = loc.lat - 40
    lngdist = loc.lng + 89

    if latdist > 1 or latdist < -1 or lngdist > 1 or lngdist < -1:
        print('Distance Violation!')
        print(latdist)
        print(lngdist)
        return

    # if no new filename, add .dec
    if not out_filename:
        out_filename = in_filename + '.dec'

    # open file and decrypt with key, we know the encryption scheme
    with open(in_filename, 'rb') as infile:
        # take the filesize and iv first
        filesize = struct.unpack('<Q', infile.read(8))[0]
        iv = infile.read(16)
        filelat = struct.unpack('<f', infile.read(4))
        filelng = struct.unpack('<f', infile.read(4))
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            encrypted_filesize = os.path.getsize(in_filename)
            # the filesize, IV, lng, and lat metadata
            pos = 8 + 16 + 4 + 4
            while pos < encrypted_filesize:
                chunk = infile.read(chunksize)
                pos += len(chunk)
                chunk = encryptor.decrypt(chunk)
                if pos == encrypted_filesize:
                    chunk = unpad(chunk, AES.block_size)
                outfile.write(chunk) 

    print("Decryption Finished!")

# a function to calculate an hmac, used on exit with monitor and record
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

# monitor the users operations
def data_op_monitor(delay):
    while(True):
        time.sleep(5)
        os.system('ps -A | grep cp >> op_monitor.txt')

# record the users operations
def data_op_record(op):
    with open('op_trace.txt', 'a+') as outfile:
        outfile.write( pwd.getpwuid(os.getuid())[0] + ' ' + op + ' ' + str(time.asctime(time.localtime(time.time()))) + "\n")
        outfile.flush()


# main function to present user with options to call other functions
if __name__=='__main__':

    # start monitoring and recording user
    os.system('rm -rf ./op_trace.txt')
    os.system('rm -rf ./op_monitor.txt')

    # get users location for geosense and geofence
    loc = geocoder.ip('me')
    print(loc)
    print(loc.latlng)

    # setup geopy for calculating distance from anchor point\
    geolocator = Nominatim(user_agent='JG_SPD')

    # get the user's key, must be same as encrypted key to decrypt
    passwd = getpass.getpass("input your key:\n")
    hash_pwd = SHA256.new()
    hash_pwd.update(bytes(passwd, encoding = "utf-8"))
    _thread.start_new_thread(data_op_monitor,(5,))

    # give user choices to encrypt, decrypt, remove, show logs, or quit
    while True:
        op = input("Choose your operation:\n1. encrypt a file\n2. decrypt a file\n3. remove a file\n4. dumplog\n5. exit\n -> ")
        if op == '5':
            # user quit, get hmac and break
            cal_hmac(hash_pwd.hexdigest().encode('utf-8'), 'op_trace.txt')
            cal_hmac(hash_pwd.hexdigest().encode('utf-8'), 'op_monitor.txt')
            break
        elif op == '1':
            # encrypt, give prompts for optional filenames and call encrypt
            input_path = input("Input plaintext file path:\n")
            output_path = input("Input encrypted file path:\n")
            file_anchor = input("Input file anchor address:\n")
            allowed_distance = input("Input allowed distance from anchor point in miles:\n")

            data_op_record('encrypt')
            encrypt_file(hash_pwd.hexdigest()[0:32].encode('utf-8'), input_path, output_path, file_anchor, allowed_distance)
        elif op == '2':
            # decrypt, give prompts for optional filenames and call decrypt
            input_path = input("Input encrypted file path:\n")
            output_path = input("Input plaintext file path:\n")
            data_op_record('decrypt')
            decrypt_file(hash_pwd.hexdigest()[0:32].encode('utf-8'), input_path, output_path)
        elif op == '3':
            # user wants to remove a file, ask which one and delete
            input_path = input("Input path of the file you want to delete:\n")
            data_op_record('delete')
            os.system("rm -rf " + input_path)
            print("Delete Finished!\n")
        elif op == '4':
            # user wants to see the logs of this session, pretty print them
            print("====================data operation records====================\n");
            os.system("cat ./op_trace.txt")
            print("=================global data operation records================\n");
            os.system("cat ./op_monitor.txt")
           
# user broke out with option 5 to exit, program ends