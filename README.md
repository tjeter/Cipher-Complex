# Cipher-Complex
Cipher tool that allows the use of Caesar Cipher, Vigenere Cipher, Playfair Cipher, Monoalphabetic Cipher, Base64, XOR, and Hashing (SHA256, SHA512, and MD5)

Project Description:
---------------------
There are many cipher techniques and tools that can be found online. The problem is that these programs are all stand-alone in nature. I propose a menu-oriented command line tool, the Cipher Complex, that incorporates each of these techniques and tools as executable options from a printed list based on a user’s input choice. Some of the combined cipher techniques are Caesar, Vigenere, Playfair, and Monoalphabetic. The Cipher Complex also includes Base64 operations, XOR operations, and Hashing functions such as SHA256, SHA512, and MD5. This will speed up the overall time it takes to execute each tool because they are all conveniently in the same program now. Time is saved from opening multiple program files as well. 

Project Design:
----------------
The Cipher Complex is written in the Python programming language. Each of the cipher tools were written in Python as stand-alone programs so to keep it simple, Python was the language to use during the combining process. This was much easier than converting to another language. The program is menu-oriented so at the execution a menu is printed with all of the options available to the user from a function called cipherList().

  1.)	Caesar Cipher
  2.)	Vigenere Cipher
  3.)	Playfair Cipher
  4.)	Monoalphabetic Cipher
  5.)	Base64
  6.)	XORed1
  7.)	Hashing --> MD5, SHA256, SHA512
  
From this, a user types in the corresponding number for the technique they want to use from the menu. Based on that number, the program jumps to the specific function that corresponds with the chosen number from the menu and carries out that option. Each technique has its own function within the program. The specific imported libraries are all at the top of the program as well for easy use.

Project Implementation Steps:
------------------------------
1.)	Setup the menu in cipherList() and make sure the user is prompted after it prints

2.)	Add the proper imports in the header of the program for all the tools that are planned to be incorporated into the program

3.)	Define functions for each tool planned to be incorporated such as:
    a. def caesar():
    b. def vigenere():
    c. def playfair():
    
4.)	Gather each program in its stand-alone form
    a.	Some only encrypt --> add decryption functionality
    b.	Some encrypt and immediately decrypt --> Give the user the option to decrypt instead of doing it immediately
    c.	In the case of the hashing function, another menu was made within that function to give the option of which hashing method the user wanted to use and each of those hashing methods have their own functions within the overall hashing function --> SHA256, SHA512, or MD5
    
5.)	The end of the program is simply seven conditional if statements. These test the option the user inputs at the very beginning of the program and depending on what number is input, the correlating function is then called and executed
