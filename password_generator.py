import argparse
import time

# Define character sets
UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

# Simple linear congruential generator (LCG) for pseudo-random numbers
class SimpleLCG:
    def __init__(self, seed=time.time()):
        self.modulus = 2**32
        self.a = 1103515245
        self.c = 12345
        self.state = int(seed) & (self.modulus - 1)

    def random(self):
        self.state = (self.a * self.state + self.c) % self.modulus
        return self.state / self.modulus

    def randint(self, min_value, max_value):
        return int(self.random() * (max_value - min_value + 1)) + min_value

def generate_password(length, include_uppercase, include_lowercase, include_digits, include_special):
    if length < 1:
        raise ValueError("Password length must be at least 1")

    char_pool = ''
    if include_uppercase:
        char_pool += UPPERCASE_LETTERS
    if include_lowercase:
        char_pool += LOWERCASE_LETTERS
    if include_digits:
        char_pool += DIGITS
    if include_special:
        char_pool += SPECIAL_CHARACTERS

    if not char_pool:
        raise ValueError("At least one character type must be selected")

    lcg = SimpleLCG()
    password = ''.join(char_pool[lcg.randint(0, len(char_pool) - 1)] for _ in range(length))
    return password

def main():
    parser = argparse.ArgumentParser(description="Random Password Generator")
    parser.add_argument('-l', '--length', type=int, required=True, help="Length of the password")
    parser.add_argument('-u', '--uppercase', action='store_true', help="Include uppercase letters")
    parser.add_argument('-lw', '--lowercase', action='store_true', help="Include lowercase letters")
    parser.add_argument('-d', '--digits', action='store_true', help="Include digits")
    parser.add_argument('-s', '--special', action='store_true', help="Include special characters")

    args = parser.parse_args()

    try:
        password = generate_password(args.length, args.uppercase, args.lowercase, args.digits, args.special)
        print("Generated Password:", password)
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()

