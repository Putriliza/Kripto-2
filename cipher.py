from operations import *
from datetime import datetime
import time

def encrypt(plaintext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=16):
    # start timer
    start = time.time()

    key = charToBytes(key)
    IV = charToBytes(IV)
    if len(key) != 16 and IV != 16:
        print("ERROR! Key must be 16 bytes long")
        return []
    plaintext = bytes(plaintext)

    # add padding to plaintext to be multiple of 16
    plaintext = plaintext + bytes(16 - len(plaintext) % 16)
    
    # split plaintext into blocks of 16 bytes
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    # make 16 keys
    keys = keySchedule(key, num_rounds)

    # encrypt each block
    for k in keys:
        for i in range(len(blocks)):
            if i == 0:
                blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(IV,byteorder="big")).to_bytes(16,byteorder="big")
            else:
                blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(blocks[i-1],byteorder="big")).to_bytes(16,byteorder="big")
            blocks[i] = (int.from_bytes(blocks[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")
            
            blocks[i] = P1Process(blocks[i])
            blocks[i] = r4Shift(blocks[i])
            blocks[i] = S1Process(blocks[i])

    # join blocks of 16 bytes into one ciphertext
    ciphertext = b''
    for i in range(len(blocks)):
        ciphertext += blocks[i]

    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return ciphertext

def decrypt(ciphertext, key, IV='\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', num_rounds=16):
    #start timer
    start = time.time()

    key = charToBytes(key)
    IV = charToBytes(IV)
    if len(key) != 16 and IV != 16:
        print("ERROR! Key must be 16 bytes long")
        return []
    ciphertext = bytes(ciphertext)
    
    # split ciphertext into blocks of 16 bytes
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    resultingBlock = blocks.copy()

    # make 16 keys
    keys = keySchedule(key, num_rounds)
    keys = keys[::-1]

    # encrypt each block
    for k in keys:
        for i in range(len(resultingBlock)):
            resultingBlock[i] = S1Process_reverse(blocks[i])
            resultingBlock[i] = r4Shift_reverse(resultingBlock[i])
            resultingBlock[i] = P1Process_reverse(resultingBlock[i])
            
            resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(k,byteorder="big")).to_bytes(16,byteorder="big")

            if i == 0:
                resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(IV,byteorder="big")).to_bytes(16,byteorder="big")
            else:
                resultingBlock[i] = (int.from_bytes(resultingBlock[i],byteorder="big") ^ int.from_bytes(blocks[i-1],byteorder="big")).to_bytes(16,byteorder="big")
        blocks = resultingBlock.copy()

    # join blocks of 16 bytes into one ciphertext
    plaintext = b''
    for i in range(len(resultingBlock)):
        plaintext += resultingBlock[i]
    
    # end timer
    end = time.time()
    print("Time taken: ", end - start)

    return plaintext.rstrip(b'\x00')


# key = "afanlizaubai1234"

# plaintext = "once upon a time, lived 3 students in a university. they were very happy and they lived happily ever after."


if __name__ == "__main__":
    print("Welcome to Omnium block cipher!")
    print("Operation:")
    print("1. Encrypt")
    print("2. Decrypt")
    try:
        op = int(input("Choose operation (1-2): "))
    except:
        print("Invalid input")
        exit()

    if (op == 1):
        plaintext = input("Plaintext (.txt file): ")
        file = open(plaintext, 'rb')
        plaintext = file.read()
    elif (op == 2):
        ciphertext = input("CipherText (.txt file): ")
        file = open(ciphertext, 'rb')
        ciphertext = file.read()
    else:
        print("Invalid input")
        exit()
    
    key = input("Key (16 byte): ")
    IV = input("Initialization Vector (16 byte). Leave blank for default: ")

    if (op == 1):
        if len(IV):
            result_ciphertext = encrypt(plaintext, key, IV=IV)
        else:
            result_ciphertext = encrypt(plaintext, key)
        file = open(f'{datetime.now().strftime("%d-%m-%Y %H.%M.%S")}.txt', 'wb')
        file.write(result_ciphertext)
        
    elif (op == 2):
        if len(IV):
            result_plaintext = decrypt(ciphertext, key, IV=IV)
        else:
            result_plaintext = decrypt(ciphertext, key)
        file = open(f'{datetime.now().strftime("%d-%m-%Y %H.%M.%S")}.txt', 'wb')
        file.write(result_plaintext)
    

    
    

    