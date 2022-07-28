import numpy as np
import hashlib


def sign(message):
    print(f"Message to sign: {message}")
    upper_bound = pow(2, 64) - 1
    private_zero, private_one, public_zero, public_one = [], [], [], []

    # Generate private keys.
    for _ in range(256):
        zero_extend, one_extend = [], []
        for _ in range(4):
            x, y = np.random.randint(0, upper_bound, dtype="uint64"), np.random.randint(0, upper_bound, dtype="uint64")
            zero_extend.append(x)
            one_extend.append(y)
        zero_extend, one_extend = np.array(zero_extend), np.array(one_extend)
        x, y = int.from_bytes(zero_extend.tobytes(), 'big'), int.from_bytes(one_extend.tobytes(), 'big') #https://stackoverflow.com/questions/68215238/numpy-256-bit-computing
        private_zero.append(str(x))
        private_one.append(str(y))
    
    # Generate public keys.
    public_zero, public_one = list(map(hash, private_zero)), list(map(hash, private_one))

    # Hash message.
    hashed_sign = hashlib.sha256(message.encode('utf-8')).hexdigest() #https://datagy.io/python-sha256/
    print(hashed_sign)

    # Partially expose private key to create signature.
    signature = []
    pointer = 0
    for char in hashed_sign:
        hex_to_int = int(char, base=16)
        bit_string = str(bin(hex_to_int))[2:].zfill(4) # Convert every hex character to a 4 bit string removing the '0b' prefix.
        for bit in bit_string:
            if bit == 0:
                signature.append(private_zero[pointer])
            else:
                signature.append(private_one[pointer])

            pointer += 1
    
    return signature, public_zero, public_one


def verify(signature, public_zero, public_one, message):
    pointer = 0
    hashed_message = hash(message)
    is_valid = True

    for char in hashed_message:
        hex_to_int = int(char, base=16)
        bit_string = str(bin(hex_to_int))[2:].zfill(4) # Convert every hex character to a 4 bit string removing the '0b' prefix.
        for bit in bit_string:
            if bit == 0:
                public_block = public_zero[pointer]
            else:
                public_block = public_one[pointer]

            hashed_sign = hash(signature[pointer])
            is_valid = public_block == hashed_sign
            pointer += 1
            if not is_valid:
                print("Error: Signature not valid")
                return False
    print("Passed! Signature valid.")
    return is_valid

def hash(input):
    hashed_input = hashlib.sha256(input.encode('utf-8')).hexdigest()
    return hashed_input



if __name__ == "__main__":
    user_message = input("Enter the message you want to sign with: ")
    signature, public_zero, public_one = sign(user_message)
    verify(signature, public_zero, public_one, user_message)

    signature_mal, public_zero_mal, public_one_mal = sign("this is an attack")
    verify(signature_mal, public_zero, public_one, user_message) # Malicious attack


    print()
