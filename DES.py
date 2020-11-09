#Name: Andrés Aguilar
#FSUID: aea17d
#Due Date: 11/5/2020
#The program in this file is the individual work of Andrés Aguilar 

import random

INITIAL_PERMUTATION = [58, 50, 42, 34, 26, 18, 10, 2,
                        60,	52,	44,	36,	28,	20,	12,	4,
                        62,	54,	46,	38,	30,	22,	14,	6,
                        64,	56,	48,	40,	32,	24,	16,	8,
                        57,	49,	41,	33,	25,	17,	9,	1,
                        59,	51,	43,	35,	27,	19,	11,	3,
                        61,	53,	45,	37,	29,	21,	13,	5,
                        63,	55,	47,	39,	31,	23,	15,	7]

EXPANSION_FUNCTION = [32,	1,	2,	3,	4,	5,
                        4,	5,	6,	7,	8,	9,
                        8,	9,	10,	11,	12,	13,
                        12,	13,	14,	15,	16,	17,
                        16,	17,	18,	19,	20,	21,
                        20,	21,	22,	23,	24,	25,
                        24,	25,	26,	27,	28,	29,
                        28,	29,	30,	31,	32,	1]

PERMUTED_CHOICE_2 = [14, 17, 11, 24, 1,	5,
                        3,	28,	15,	6,	21,	10,
                        23,	19,	12, 4,	26,	8,
                        16,	7,	27,	20,	13,	2,
                        41,	52,	31,	37,	47,	55,
                        30,	40,	51,	45,	33,	48,
                        44,	49,	39,	56,	34,	53,
                        46,	42,	50,	36,	29,	32]

S_BOX = [[14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7],
      [0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8],
      [4,  1,  14,  8, 13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0],
     [15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13]]

INTERMEDIATE_PERMUTATION = [16,	7,	20,	21,	29,	12,	28,	17,
                            1,	15,	23,	26,	5,	18,	31,	10,
                            2,	8,	24,	14,	32,	27,	3,	9,
                            19,	13,	30,	6,	22,	11,	4,	25]

FINAL_PERMUTATION = [40, 8, 48,	16,	56,	24,	64,	32,
                    39,	7,	47,	15,	55,	23,	63,	31,
                    38,	6,	46,	14,	54,	22,	62,	30,
                    37,	5,	45,	13,	53,	21,	61,	29,
                    36,	4,	44,	12,	52,	20,	60,	28,
                    35,	3,	43,	11,	51,	19,	59,	27,
                    34,	2,	42,	10,	50,	18,	58,	26,
                    33,	1,	41,	9,	49,	17,	57,	25]


#Encryptor function
def encrypt(plaintext, key):

    encryption = ""
    for i in range(0, len(plaintext), 8):

        #Separate plaintext into 8 character chunks
        textChunk = plaintext[i : min(i + 8, len(plaintext))] 
        
        #Generate 64-bit block from ASCII values of characters in the text chunk
        block = 0
        for j in range(8):
            if j < len(textChunk):
                block |= ord(textChunk[j])
            if j != 7:
                block = block << 8

        #Encrypt block
        encryptedBlock = DES(block, key, True)

        #Add encrypted block to encrypted message
        for j in range(8):
            char = (encryptedBlock >> (j * 8)) & 255
            encryption += chr(char)

    return encryption[::-1]

#Decryptor function
def decrypt(ciphertext, key):
    
    decryption = ""
    for i in range(0, len(ciphertext), 8):

        #Separate plaintext into 8 character chunks
        textChunk = ciphertext[i : min(i + 8, len(ciphertext))] 

        #Generate 64-bit block from ASCII values of characters in the text chunk
        block = 0
        for j in range(8):
            if j < len(textChunk):
                block |= ord(textChunk[j])
            if j != 7:
                block = block << 8

        #Decrypt block
        decryptedBlock = DES(block, key, False)

        #Add encrypted block to encrypted message
        for j in range(8):
            char = (decryptedBlock >> (j * 8)) & 255
            decryption += chr(char)

    return decryption[::-1]


#Function to perform encrypt parameter comforming to Data Encryption Standard
def DES(block, key, isEncryption):
    
    #Perform intial permutation on block
    block = permutate(block, INITIAL_PERMUTATION, 64, 64)

    #Split block into 32 bit halves
    left = block >> 32
    right = block & int("ffffffff", 16)

    #If we are decrypting, we want our first key to be the last key from the encryption rounds
    #Therefore, we compute such key
    if not isEncryption:
        for _ in range(17):
            key = (key >> 55) | (key << 1)

    for _ in range(16):

        temp = right

        #Apply expansion permutation
        right = permutate(right, EXPANSION_FUNCTION, 32, 48)

        #Shift key (left or right, depending on whether we are encyrpting or decrypting), and apply PC-2
        if isEncryption:
            #Circular shift left
            key = (key >> 55) | (key << 1)
        else:
            #Circular shift right
            poppedBit = key & 1
            key = (key >> 1) | (poppedBit << 55)
        roundKey = permutate(key, PERMUTED_CHOICE_2, 56, 48)

        #XOR with key
        right ^= roundKey

        #Use S-Box to shrink back down to 32 bits
        shrunkRight = 0
        for j in reversed(range(8)):

            #Shift shrunk right to the left to allow for "concatenating" next bits
            shrunkRight <<= 4

            #Get the jth 6 bits
            sixBits = 63 & (right >> (j * 6))

            #Find the row and column
            col = (sixBits & 31) >> 1
            row = (sixBits & 1) | ((sixBits & 32) >> 4)

            #Find new 4-bit value from S-Box
            shrunkRight |= S_BOX[row][col]  
        
        right = shrunkRight

        #Apply intermediary permutation
        right = permutate(right, INTERMEDIATE_PERMUTATION, 32, 32)

        #XOR with left half
        right = left ^ right
        left = temp

    #Swap right and left side one final time
    right, left = left, right

    #Merge left and right halves
    block = (left << 32) | right
    
    #Perform final permutation
    block = permutate(block, FINAL_PERMUTATION, 64, 64)

    return block

def permutate(bits, permutationType, inputSize, outputSize):

    output = 0

    #Rearrange the bits acording to specified permutation
    for i in range(outputSize):
        bit = bits & (1 << (inputSize - permutationType[i]))

        #Set bit at desired position of output
        if bit:
            output |= 1 << (outputSize - i - 1)
    
    return output


print()
print("DES Implementation:")

#Prompt user to enter text to be processed
text = input("Enter text to encrypt (\"Exit\" to quit): ")

#Generate key from random number generator
KEY = random.getrandbits(56)

#Keep prompting user for input, unless user input is "Exit"
while text != "Exit":

    #Both encrypt and decrypt the text
    encryptedText = encrypt(text, KEY)
    decryptedText = decrypt(encryptedText, KEY)

    #Display the text after encryption and decryption
    print("Encrypted text: ", encryptedText)
    print("Decrypted text: ", decryptedText)

    #Prompt user to enter text to be processed
    text = input("Next text (\"Exit\" to quit): ")

print()