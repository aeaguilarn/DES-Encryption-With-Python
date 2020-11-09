# DES-Encryption-With-Python
This program is a modified version of the Data Encryption Standard using Python. This program uses bit manipulation, rather than iterables, to perform the required permutations for encryption and decryption. This makes the program execute much faster.

# A Few Things To Watch Out For
This is a MODIFIED version of the DES algorithm. The main differences are that only one S-Box is being used, the Key Scheduling is done by only performing a circular shift on the entire 56-bit key (the direction depends on whether we are encrypting or decrypting) and then applying PC-2, and finally we are skipping applying PC-1.
