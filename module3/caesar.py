"""
Encrypts the message "hello world!" using a Caesar cipher shift of 7.
"""

def caesar_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            # keep case (upper/lower) intact
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + key) % 26 + start)
        else:
            result += char  # non-alphabetic chars stay the same
    return result

# the message
message = "hello world!"
key = 7

# encrypt the message
encrypted_message = caesar_encrypt(message, key)

# print results
print("Original message:", message)
print(f"Encrypted with key={key}:", encrypted_message)
