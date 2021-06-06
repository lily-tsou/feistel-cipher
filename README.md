# feistel-cipher
---
This feistel cipher was an assignment from Portland State University's CS 585: Cryptography course. It is based on [Twofish](https://en.wikipedia.org/wiki/Twofish) and [Skipjack](https://en.wikipedia.org/wiki/Skipjack_(cipher)). <br>
The cipher uses at 64-bit block size and an 80-bit key. Because it is a feistel cipher, both encryption and decryption use the same algorithm, with the only difference being that decryption uses the keys in reverse order. <br>
Please note that this project was created for educational purposes and should not be used for actual encryption. <br>
For more on feistel ciphers, visit the [wikipedia](https://en.wikipedia.org/wiki/Feistel_cipher) page or watch this [video](https://www.youtube.com/watch?v=FGhj3CGxl8I).<br>

## To run:
After compiling and creating a target (e.g., "feistel"): <br>
``./feistel [option] [file_in] [file_out]``<br>
Option is either "e", indicating encryption, or "d", indicating decryption. <br>
file_in is the name of the file to be read and either encrypted or decrypted, and file_out is the where the resulting encrypted or decrypted text will be written. <br>
For example: <br>
``./feistel e plaintext.txt cipher.txt``<br>
For decryption, file_in must be represented as 64-bit hex blocks (16 hex digits) separated by a space or newline, and not prefaced with "0x". <br>
You must have a key.txt file in your directory in order for this to run. The contents of this file must be an 80-bit key represented as 20 hex digits, not prefaced with "0x".
