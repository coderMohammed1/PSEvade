from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad # type: ignore
import base64
from random import randbytes
import argparse

def encrypt(input_file,output_file): 
    # AES-256 key (32 bytes) and IV (16 bytes) – base64
    key = randbytes(32)
    iv  = randbytes(16)
    with open(input_file, "rb") as f:
        data = f.read()
        
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    with open(output_file, "wb") as f:
        f.write(ciphertext)
    print("[+] Encrypted ->", output_file)
    print("-"*15)
    print(f"the key:{base64.b64encode(key)}",f"The IV: {base64.b64encode(iv)}")
    print("-"*15)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--script", help="The powershell script you want to encrypt.")
    parser.add_argument("-o", "--out", help="Output encrypted file.")
    args = parser.parse_args()
    
    if args.script and args.out:
        encrypt(args.script,args.out)
        print("Now check decrypt.ps1 for decryption and runing!")
    else:
        print("pleas use --help to show the help menue")
        
if __name__ == "__main__":
    main()
