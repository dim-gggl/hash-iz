import string
import random
from flask import jsonify

SIMPLE_CHARS = list(string.ascii_letters * 5 + string.digits * 5)
raw_special_chrs = list(string.punctuation * 4)
unstable_chrs = ["\'", "\\", "/", '"', "<", ">", "|", "(", ")", "[", "]", "{", "}"]
special_chrs = []

for chr in raw_special_chrs:
    if chr not in unstable_chrs:
        special_chrs.append(chr)

ONLY_SPECIAL_CHARS = special_chrs
special_chrs.extend(SIMPLE_CHARS)
random.shuffle(special_chrs)

MIXED_CHARS = special_chrs

def password_generator(num_char=16, special=True):
    if special:
        chars = MIXED_CHARS.copy()
    else:
        chars = SIMPLE_CHARS.copy()
    random.shuffle(chars)
    return ''.join(random.sample(chars, num_char))
