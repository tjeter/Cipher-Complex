#Purpose: Combine 7 known cipher techniques into one menu-oriented tool
#Date: November 18, 2020

import string
import random
import base64
import itertools
import hashlib

print("The following is a list of cipher techniques you can use: ")

##menu = {}
##menu['1'] = "Caesar Cipher"
##menu['2'] = "Vigenere Cipher"
##menu['3'] = "Playfair Cipher"
##menu['4'] = "Column Transposition Cipher"
##menu['5'] = "Advanced Encryption Standard (AES)"
##menu['6'] = "Data Encryption Standard (DES)"
##
##print(menu)

print()
def cipherList():
    print("1.) Caesar Cipher")
    print("2.) Vigenere Cipher")
    print("3.) Playfair Cipher")
    print("4.) Monoalphabetic Cipher")
    print("5.) Base64")
    print("6.) XORed1")
    print("7.) Hashing --> MD5, SHA256, SHA512")

cipherList()
print()

option = input("Enter the cipher technique you'd like to use based on its listed number: ")

def caesar():
    MAX_KEY_SIZE = 26
    def getMode():
        while True:
            print('Do you wish to encrypt or decrypt a message?')
            mode = input().lower()
            if mode in 'encrypt e decrypt d'.split():
                return mode
            else:
                print('Enter either "encrypt" or "e" or "decrypt" or "d".')

    def getMessage():
        print('Enter your message: ')
        return input()

    def getKey():
        key = 0
        while True:
            print('Enter the key number (1-%s)' % (MAX_KEY_SIZE))
            key = int(input())
            if(key >= 1 and key <= MAX_KEY_SIZE):
                return key

    def getTranslatedMessage(mode, message, key):
        if mode[0] == 'd':
            key = -key
        translated = ''
        for symbol in message:
            if symbol.isalpha():
                num = ord(symbol)
                num += key
                if symbol.isupper():
                    if num > ord('Z'):
                        num -= 26
                    elif num < ord('A'):
                        num += 26
                elif symbol.islower():
                    if num > ord('z'):
                        num -= 26
                    elif num < ord('a'):
                        num += 26
                translated += chr(num)
            else:
                translated += symbol
        return translated

    mode = getMode()
    message = getMessage()
    key = getKey()

    print('Your translated text is: ')
    print(getTranslatedMessage(mode, message, key))

    print()
    print("If you chose to encrypt a message, you will need to re-run the program to decrypt it")


def vigenere():
    def vigenere_enc():
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        input_string = ""
        enc_key = ""
        enc_string = ""

        # Takes encrpytion key from user
        enc_key = input("Please enter an encryption key of your choice: ")
        enc_key = enc_key.lower()

        # Takes string from user
        input_string = input("Please enter a string of text: ")
        input_string = input_string.lower()

        # Lengths of input_string
        string_length = len(input_string)

        # Expands the encryption key to make it longer than the inputted string
        expanded_key = enc_key
        expanded_key_length = len(expanded_key)
        while expanded_key_length < string_length:
            # Adds another repetition of the encryption key
            expanded_key = expanded_key + enc_key
            expanded_key_length = len(expanded_key)

        key_position = 0
        for letter in input_string:
            if letter in alphabet:
                # cycles through each letter to find it's numeric position in the alphabet
                position = alphabet.find(letter)

                # moves along key and finds the characters value
                key_character = expanded_key[key_position]
                key_character_position = alphabet.find(key_character)
                key_position = key_position + 1

                # changes the original of the input string character
                new_position = position + key_character_position
                if new_position > 26:
                    new_position = new_position - 26
                new_character = alphabet[new_position]
                enc_string = enc_string + new_character
            else:
                enc_string = enc_string + letter
        return(enc_string)


    def vigenere_dec():
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        input_string = ""
        dec_key = ""
        dec_string = ""

        # Takes encrpytion key from user
        print()
        dec_key = input("Please enter your encryption key for decrypting: ")
        dec_key = dec_key.lower()

        # Takes string from user
        input_string = input("Please enter the encrypted string of text: ")
        input_string = input_string.lower()

        # Lengths of input_string
        string_length = len(input_string)

        # Expands the encryption key to make it longer than the inputted string
        expanded_key = dec_key
        expanded_key_length = len(expanded_key)
        while expanded_key_length < string_length:
            # Adds another repetition of the encryption key
            expanded_key = expanded_key + dec_key
            expanded_key_length = len(expanded_key)

        key_position = 0
        for letter in input_string:
            if letter in alphabet:
                # cycles through each letter to find it's numeric position in the alphabet
                position = alphabet.find(letter)

                # moves along key and finds the characters value
                key_character = expanded_key[key_position]
                key_character_position = alphabet.find(key_character)
                key_position = key_position + 1

                # changes the original of the input string character
                new_position = position - key_character_position
                if new_position > 26:
                    new_position = new_position + 26
                new_character = alphabet[new_position]
                dec_string = dec_string + new_character
            else:
                dec_string = dec_string + letter
        return(dec_string)

    # Testing
    print(vigenere_enc())
    print(vigenere_dec())


def playfair():
    key = input("Enter key: ")
    key = key.replace(" ", "")
    key = key.upper()

    def matrix(x, y, initial):
        return [[initial for i in range(x)] for j in range(y)]

    result = list()
    for c in key: #storing key
        if(c not in result):
            if(c == 'J'):
                result.append('I')
            else:
                result.append(c)
    flag = 0
    for i in range(65, 91): #storing other character
        if(chr(i) not in result):
            if(i == 73 and chr(74) not in result):
                result.append("I")
                flag = 1
            elif(flag == 0 and i == 73 or i == 74):
                pass    
            else:
                result.append(chr(i))

    k = 0
    my_matrix = matrix(5, 5, 0) #initialize matrix
    for i in range(0, 5): #making matrix
        for j in range(0, 5):
            my_matrix[i][j] = result[k]
            k += 1

    def locindex(c): #get location of each character
        loc = list()
        if(c == 'J'):
            c = 'I'
        for i, j in enumerate(my_matrix):
            for k, l in enumerate(j):
                if(c == l):
                    loc.append(i)
                    loc.append(k)
                    return loc

    def encrypt():  #Encryption
        msg = str(input("Enter the message to encrypt: "))
        msg = msg.upper()
        msg = msg.replace(" ", "")
        
        i = 0
        for s in range(0, len(msg)+ 1, 2):
            if(s < len(msg)-1):
                if(msg[s] == msg[s + 1]):
                    msg = msg[:s + 1] + 'X' + msg[s + 1:]
        if(len(msg) % 2 != 0):
            msg = msg[:] + 'X'
        print("Ciphertext: ", end = ' ')
        while(i < len(msg)):
            loc = list()
            loc = locindex(msg[i])
            loc1 = list()
            loc1 = locindex(msg[i+1])
            if(loc[1] == loc1[1]):
                print("{}{}".format(my_matrix[(loc[0] + 1) % 5][loc[1]], my_matrix[(loc1[0] + 1) % 5][loc1[1]]), end = ' ')
            elif(loc[0] == loc1[0]):
                print("{}{}".format(my_matrix[loc[0]][(loc[1] + 1) % 5], my_matrix[loc1[0]][(loc1[1] + 1) % 5]), end = ' ')  
            else:
                print("{}{}".format(my_matrix[loc[0]][loc1[1]], my_matrix[loc1[0]][loc[1]]), end = ' ')    
            i = i + 2        

    def decrypt():  #decryption
        msg = str(input("Enter the ciphertext: "))
        msg = msg.upper()
        msg = msg.replace(" ", "")
        print("Plaintext: ", end = ' ')

        i = 0
        while(i < len(msg)):
            loc = list()
            loc = locindex(msg[i])
            loc1 = list()
            loc1 = locindex(msg[i + 1])
            if(loc[1] == loc1[1]):
                print("{}{}".format(my_matrix[(loc[0] - 1) % 5][loc[1]], my_matrix[(loc1[0] - 1) % 5][loc1[1]]), end = ' ')
            elif(loc[0] == loc1[0]):
                print("{}{}".format(my_matrix[loc[0]][(loc[1] - 1) % 5], my_matrix[loc1[0]][(loc1[1] - 1) % 5]), end = ' ')  
            else:
                print("{}{}".format(my_matrix[loc[0]][loc1[1]], my_matrix[loc1[0]][loc[1]]), end = ' ')    
            i = i + 2        

    while(1):
        choice = int(input("\n 1.) Encryption \n 2.) Decryption \n 3.) Quit \n If you enter 3, the entire program will terminate \n"))
        if(choice == 1):
            encrypt()
        elif(choice == 2):
            decrypt()
        elif(choice == 3):
            exit()
        else:
            print("Please choose 1, 2, or 3")


def monoalphabetic():
    def random_monoalpha_cipher(pool = None):
       if pool is None:
          pool = string.ascii_letters + string.digits
       original_pool = list(pool)
       shuffled_pool = list(pool)
       random.shuffle(shuffled_pool)
       return dict(zip(original_pool, shuffled_pool))

    def inverse_monoalpha_cipher(monoalpha_cipher):
       inverse_monoalpha = {}
       for key, value in monoalpha_cipher.items():
          inverse_monoalpha[value] = key
       return inverse_monoalpha

    def encrypt_with_monoalpha(message, monoalpha_cipher):
       encrypted_message = []
       for letter in message:
          encrypted_message.append(monoalpha_cipher.get(letter, letter))
       return ''.join(encrypted_message)

    def decrypt_with_monoalpha(encrypted_message, monoalpha_cipher):
       return encrypt_with_monoalpha(
          encrypted_message,
          inverse_monoalpha_cipher(monoalpha_cipher)
       )

    cipher = random_monoalpha_cipher()
    print(cipher)
    message = input("Enter a message to encrypt: ")
    encrypted = encrypt_with_monoalpha(message, cipher)
    decrypted = decrypt_with_monoalpha(encrypted, cipher)

    print(encrypted)
    choice = input("Do you wish to decrypt the message? \n")
    if(choice == 'Y' or choice == 'y' or choice == 'YES' or choice == 'Yes' or choice == 'yes'):
       print(decrypted)
    else:
       exit()


def base():
    data_str = input("Enter input data: \n")
    data_bytes = data_str.encode("utf-8")
    encoded_data = base64.b64encode(data_bytes)

    print("Base64 encoded data: " + str(encoded_data) + "\n")
    
    choice = input("Do you wish to decode the data? \n")
    if(choice == 'Y' or choice == 'y' or choice == 'YES' or choice == 'Yes' or choice == 'yes'):
        decoded_data = base64.b64decode(encoded_data)
        print("Decoded data is: " + str(decoded_data))
    else:
        exit()


def xor():
    def xor_crypt_string(data, key = 'CompCyber', encode = False, decode = False):
       if(decode):
          data = base64.decodebytes(data).decode('utf-8')
       xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, itertools.cycle(key)))
       if(encode):
          return base64.encodebytes(xored.encode('utf-8')).strip()
       return xored

    secret_data = input("Please enter data to XOR: \n")
    print()
    en_data = xor_crypt_string(secret_data, encode = True)
    print("The cipher text is: ")
    print(en_data)
    print()

    choice = input("Do you wish to decode the data? \n")
    if(choice == 'Y' or choice == 'y' or choice == 'YES' or choice == 'Yes' or choice == 'yes'):
        dec_data = xor_crypt_string(en_data, decode = True)
        print("The plain text decoded is: ")
        print(dec_data)
    else:
        exit()


def hashes():
    # printing available algorithms
    print(hashlib.algorithms_guaranteed)

    # initializing a string
    # the string will be hashed using either 'sha256', 'sha512', or 'md5'
    message = input("Please enter a message to be hashed: \n")
    print("Message to be hashed: ", message)

    # convert the string to bytes using 'encode'
    # hash functions only accepts encoded strings
    encoded_name = message.encode()

    def hashList():
        print("1.) SHA256")
        print("2.) SHA512")
        print("3.) MD5")

    hashList()
    print()

    option = input("Enter the hash technique you'd like to use based on its listed number: ")

    def sha256():
        hashed_name = hashlib.sha256(encoded_name)
        print("Object: ", hashed_name)
        print("Hexadecimal format: ", hashed_name.hexdigest())

        #To generate, sequence of bytes in utf-8
        print(hashed_name.digest())

    def sha512():
        hashed_name = hashlib.sha512(encoded_name)
        print("Object: ", hashed_name)
        print("Hexadecimal format: ", hashed_name.hexdigest())

        #To generate, sequence of bytes in utf-8
        print(hashed_name.digest())

    def md5():
        hashed_name = hashlib.md5(encoded_name)
        print("Object: ", hashed_name)
        print("Hexadecimal format: ", hashed_name.hexdigest())

        #To generate, sequence of bytes in utf-8
        print(hashed_name.digest())

    if(option == '1'):
        sha256()

    if(option == '2'):
        sha512()

    if(option == '3'):
        md5()


if(option == '1'):
    caesar()

if(option == '2'):
    vigenere()

if(option == '3'):
    playfair()

if(option == '4'):
    monoalphabetic()

if(option == '5'):
    base()

if(option == '6'):
    xor()

if(option == '7'):
    hashes()

