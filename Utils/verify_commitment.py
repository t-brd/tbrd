import time
import hashlib

valid = False
USS_key = 'f8c83f61502a660fb67cee4525d4868aeb32575dcc542aa5bc548309c537b43f'
USS_key = bytes.fromhex(USS_key)

key_observed = '28aa3ee69ff6ec6d9238ac68965587ced5a611983527d2425c4245fa4fb0ea22'
key_observed = bytes.fromhex(key_observed)


start_time = time.time()

hash_key = key_observed

while valid == False:
    
    hash_key = hashlib.sha256(hash_key).digest() 

    if hash_key == USS_key:
        valid = True
        time_elapsed = time.time() - start_time
        print('Key chain in use is VALID')

    print('')
    print(hash_key.hex())
    print(USS_key.hex())
    print('')

print(time_elapsed)