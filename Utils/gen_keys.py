import secrets
import hashlib
import argparse

parser = argparse.ArgumentParser(description="Testing utility to generate TBRD keys")
parser.add_argument("-n","--number", type=int, default=10, help="number of keys to generate")
parser.add_argument("-o","--outfile", type = str, help="filenname for key file")
args = parser.parse_args()
OUTPUT_FILE = args.outfile
NUM_KEYS = args.number # Number of keys to generate
KEY_SIZE = 32 # Each key is 32 bytes

def generate_rand_key():
    random_bytes = secrets.token_bytes(32)
    return random_bytes

def generate_int_keys(start_key, num_keys):
    
    keys = [] # Generate list to hold keys
    keys.append(start_key)

    for i in range(num_keys):
        data = keys[i]
        hash_key = hashlib.sha256(data).digest()
        keys.append(hash_key)

    return keys[1:num_keys+1]

def save_keys_to_file(keys, filename):
    with open(filename, "w") as file:
        for key in keys:
            file.write(key.hex() + "\n")

start_key = generate_rand_key() # This key never leaves the TEE

print('Starting Key, never leaves TEE')
print(start_key.hex())
print('')

# Generate Interval keys
int_keys = generate_int_keys(start_key, NUM_KEYS)    

print('Interval keys')
for i in range(NUM_KEYS):
    print(int_keys[i].hex())

# Save keys to a file
save_keys_to_file(int_keys, OUTPUT_FILE)
print(f"\nInterval keys saved to {OUTPUT_FILE}")

