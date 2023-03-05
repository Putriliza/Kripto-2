def hex2bin(h):
    return bin(h)[2:].zfill(8)

def bin2hex(b):
    return hex(int(b, 2))

def printHexa16bytes(b):
    for i in range(16):
        print("0x{:02x}".format(b[i]), end=" ")
    print()

def bytesToChar(b):
    return ''.join(map(chr, b))

def charToBytes(c):
    arr = []
    for i in range(len(c)):
        arr.append(ord(c[i]))
    return bytes(arr)