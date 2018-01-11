from Crypto.Cipher import AES
from Crypto.Util import Padding
import binascii
import pdb

# In this project you will implement two encryption/decryption systems,
# one using AES in CBC mode and another using AES in counter mode (CTR).
# In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.
# For CBC encryption we use the PKCS5 padding scheme discussed in the lecture (14:04).
# While we ask that you implement both encryption and decryption, we will only test the decryption function.
# In the following questions you are given an AES key and a ciphertext (both are hex encoded ) and your goal is to recover the plaintext and enter it in the input boxes provided below.
# For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other.
# While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself.


def xor(arr1, arr2):
    return bytearray(a ^ b for a, b in zip(*map(bytearray, [arr1, arr2])))


def my_cbc_decrypt(key, cipher_text, block_size):
    """
    :param key:
    :param cipher_text:
    :param block_size:
    :return:
    """
    # converts hex strings to binary strings
    key = binascii.unhexlify(key.strip())
    cipher_text = binascii.unhexlify(cipher_text.strip())

    iv = cipher_text[:block_size]
    encrypted_message = cipher_text[block_size:]

    num_blocks = int(len(cipher_text) / block_size)
    decrypted = ["" for x in range(num_blocks)]
    message = ["" for x in range(num_blocks)]
    my_aes = AES.new(key, AES.MODE_ECB)
    j = 0
    for i in range(0, len(encrypted_message), block_size):
        encrypted_block = encrypted_message[i:i + block_size]
        decrypted[j] = my_aes.decrypt(encrypted_block)
        message[j] = xor(iv, decrypted[j])
        iv = encrypted_block
        j = j + 1

    padded_message = message[0]
    for i in range(1, num_blocks - 1):
        padded_message = padded_message + message[i]

    padding_amount = ord(padded_message[len(padded_message) - 1:])
    return padded_message[:-padding_amount].decode()


def cbc_decrypt(key, cipher_text, block_size):
    k = binascii.unhexlify(key.strip())
    ct = binascii.unhexlify(cipher_text.strip())
    iv = ct[:block_size]
    ct1 = ct[block_size:]
    my_aes = AES.new(k, AES.MODE_CBC, iv)
    padded_message = my_aes.decrypt(ct1)
    padding_amount = ord(padded_message[len(padded_message) - 1:])
    return padded_message[:-padding_amount].decode()


def ctr_decrypt(key, cipher_text, block_size):
    from Crypto.Util import Counter
    k = binascii.unhexlify(key.strip())  # move from string containing hex to string containing binary
    ct = binascii.unhexlify(cipher_text.strip())

    if (len(ct)) % block_size != 0:
        pad_amount = block_size - int(len(ct) % block_size)  # in bytes
        for i in range(pad_amount):
            ct = ct + bytes([pad_amount])

    iv = ct[:block_size]
    encrypted_message = ct[block_size:]

    # actual decryption
    ctr = Counter.new(len(iv)*8, initial_value=int(binascii.hexlify(iv), 16))
    my_aes = AES.new(k, AES.MODE_CTR, counter=ctr)
    msg = my_aes.decrypt(encrypted_message)  # message = the decrypted data as byte string; e.g. b'\xef\x15\x1f#\x11\xac\x8...'

    if pad_amount > 0:
        msg = msg[:-pad_amount]
    return msg.decode()  # now message is hex string


def my_ctr_decrypt(key, cipher_text, block_size):
    """
    Manual decryption of @cihper_text, given @key and the block size
    :param key: string containing hex digits. if len(key)==32, then it means 32 hex digits, i.e. 16 bytes!
    :param cipher_text: string containing hex digits
    :param block_size: the block size in *bytes*!
    :return: the decryption of @cipher_text
    """
    # For example: if len(cipher_text) == 128 hex digits, then it actually == 128*4 bits == 64 bytes == 4 blocks
    # Move from hex representation to byte representation
    k = binascii.unhexlify(key.strip())
    ct = binascii.unhexlify(cipher_text.strip())
    # Now, len(k) and and len(ct) is shorter by factor of 2

    # Check if padding is required. n byte pad is n|n|n|n...
    if (len(ct)) % block_size != 0:
        pad_amount = block_size - int(len(ct) % block_size)  # in bytes
        for i in range(pad_amount):
            ct = ct + bytes([pad_amount])  # Adds a byte-length string to ct. The value of this string = pad_amount

    iv = ct[:block_size]
    encrypted_message = ct[block_size:]
    num_blocks = int(len(encrypted_message) / block_size)

    my_aes = AES.new(k, AES.MODE_ECB)
    msg = ["" for x in range(num_blocks)]
    ctr = int(binascii.hexlify(iv), 16)
    for i in range(0, num_blocks):
        enc_iv = my_aes.encrypt(Padding.pad((ctr + i).to_bytes(block_size, byteorder='big'), block_size=16))
        msg[i] = xor(enc_iv, encrypted_message[i*block_size:(i+1)*block_size])
        msg[i] = binascii.hexlify(msg[i])

    # discard the text that is originated in the padding
    if pad_amount > 0:
        msg[i] = binascii.unhexlify(msg[i])
        msg[i] = msg[i][:-pad_amount]
        msg[i] = binascii.hexlify(msg[i])

    padded_message = msg[0]
    for i in range(1, num_blocks):
        padded_message = padded_message + msg[i]

    return binascii.unhexlify(padded_message).decode()


if __name__ == "__main__":
    block_size = 16
    cbc_inputs = []
    cbc_inputs.append(["140b41b22a29beb4061bda66b6747e14",  # 128 bits // 16 bytes == block size
              "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"])

    cbc_inputs.append(["140b41b22a29beb4061bda66b6747e14",
              "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"])

    for (key, cypher_text) in cbc_inputs:
        message = my_cbc_decrypt(key, cypher_text, block_size)
        print("Decrypted message = ", message)
        sanity_check = cbc_decrypt(key, cypher_text, block_size)
        assert(message == sanity_check)

    ctr_inputs = []
    ctr_inputs.append(["36f18357be4dbd77f050515c73fcf9f2",  # 128 bits
            "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"])
    ctr_inputs.append(["36f18357be4dbd77f050515c73fcf9f2",  # 128 bits
                       "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"])
    for (key, cypher_text) in ctr_inputs:
        message = my_ctr_decrypt(key, cypher_text, block_size)
        print("Decrypted message = ", message)
        sanity_check = ctr_decrypt(key, cypher_text, block_size)
        assert(message == sanity_check)

    print("Done.")

