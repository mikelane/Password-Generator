#!/usr/bin/env python3
"""
Generates a random password that is between 8 and 50 characters long and contains
at least 1 lowercase letter, 1 capital letter, 1 digit, and 1 punctuation mark.
"""

import string
import random
import re


def gen_password(length: int = 8) -> str:
    """
    Generate the random password
    :return: The password string
    """
    return ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length)])


def validate_password(password: str) -> bool:
    """
    Ensure the password meets the requirements.
    :param password: The password string to check
    :return: True if valid, False if not
    """
    pattern = re.compile(r'((?=.*\d)'
                         r'(?=.*[{lower}])'
                         r'(?=.*[{upper}])'
                         r'(?=.*[{punct}]))'.format(lower=string.ascii_lowercase,
                                                    upper=string.ascii_uppercase,
                                                    punct=string.punctuation))
    return bool(re.match(pattern=pattern, string=password))


def generate_valid_password(length: int = 8) -> str:
    """
    Keep generating passwords until a valid password is created
    :return: Validated password string
    """
    password = gen_password(length=length)
    while not validate_password(password=password):
        password = gen_password()
    return password


def main() -> None:
    print('Welcome to Password Generator v2.0\n')
    pass_length = 0
    while True:
        try:
            pass_length = int(input('Enter the desired password length: '))
        except (ValueError, SyntaxError):
            print('Sorry, I didn\'t understand that input. Try again.')
            continue
        if pass_length < 8:
            print('That\'s too short, please try again!')
        else:
            break
    password = generate_valid_password(pass_length)
    print('Your {} character password is: \n\n\t{}'.format(len(password), password))


if __name__ == '__main__':
    main()
