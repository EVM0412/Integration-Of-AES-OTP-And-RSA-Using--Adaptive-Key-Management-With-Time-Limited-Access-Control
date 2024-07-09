#!/usr/bin/env python3

import string
import random
import sys
abc = "abcdef"+ string.digits
one_time_pad = list(abc)
# random.shuffle(one_time_pad)
pad = "cf6add108c6adf0ad53125a3abe33544"


def encrypt(msg):
    ciphertext = ''
    for idx, char in enumerate(msg):
        charIdx = abc.index(char)
        keyIdx = one_time_pad.index(pad[idx])

        cipher = (keyIdx + charIdx) % len(one_time_pad)
        ciphertext += abc[cipher]

    return ciphertext

def decrypt(ciphertext):
    if ciphertext == '' or pad == '':
        return ''

    charIdx = abc.index(ciphertext[0])
    keyIdx = one_time_pad.index(pad[0])

    cipher = (charIdx - keyIdx) % len(one_time_pad)
    char = abc[cipher]

    return char + decrypt(ciphertext[1:], pad[1:])

if __name__ == '__main__':


    msg = input("Message: ")

    print(encrypt(msg))