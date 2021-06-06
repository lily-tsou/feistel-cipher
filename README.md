# feistel-cipher
---
This feistel cipher was an assignment from Portland Statue University's CS 586: Cryptography. It is based on [Twofish](https://en.wikipedia.org/wiki/Twofish) and [Skipjack](https://en.wikipedia.org/wiki/Skipjack_(cipher)). 
The cipher uses at 64-bit block size and an 80-bit key. Because it is a feistel cipher, both encryption and decryption use the same algorithm, with the only difference being that decryption uses the keys in reverse order.
For more on feistel ciphers, visit the [wikipedia](https://en.wikipedia.org/wiki/Feistel_cipher) page or watch this [video](https://www.youtube.com/watch?v=FGhj3CGxl8I).
---
## To run:
After compiling and creating a target (e.g., "feistel"):
./feistel [option] [file_in] [file_out]
