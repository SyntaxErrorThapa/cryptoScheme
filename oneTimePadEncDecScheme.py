import random

class OneTimePad:
    def __init__(self, message):
        self.message = self.message_to_binary(message)
        self.key = self.generate_key(self.message)
        self.cipher = self.encrypt_with_key(self.message, self.key)

    def message_to_binary(self, message):
        return ''.join(format(ord(char), '08b') for char in message)

    def binary_to_message(self, binary):
        message = ""

        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            decimal = int(byte, 2)
            character = chr(decimal)
            message += character

        return message
    
    def generate_key(self, message):
        len_message = len(message)
        return [random.randint(0, 1) for _ in range(len_message)]

    def encrypt_with_key(self, message, key):
        """
        In one time pad the len of message and key are equal
        """
        cipher = ""

        for m, k in zip(message, key):
            cipher += str((int(m)+ k) % 2)

        return cipher

    def decrypt(self, cipher):
        plain = ""
        
        # Converting back to message
        for c, k in zip(cipher, self.key):
            plain += str((int(c) + k) % 2)
        
        return self.binary_to_message(plain)
    
def main():
    # Get user input
    message = input("Enter a message to encrypt: ")
    
    # Create OneTimePad object
    otp = OneTimePad(message)
    
    # Print original message
    print(f"Original message: {message}")
    
    # Print encrypted message (cipher)
    print(f"Encrypted message (cipher): {otp.cipher}")
    
    # Decrypt and print the decrypted message
    decrypted = otp.decrypt(otp.cipher)
    print(f"Decrypted message: {decrypted}")

if __name__ == "__main__":
    main()
