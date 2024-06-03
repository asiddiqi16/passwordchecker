"""
This is a password checker that uses the https://api.pwnedpasswords.com/range/" 
API to check passwords contained within a text file has been leaked.
It takes the filepath to the text file as an input argument from command line.
Author: Ariba Siddiqi
Created as part of the Python Developer Coursework run by Andrei Neoigie from ZTM
Created: 3rd June 2024


Functions:
request_api_data(query_char)
get_password_leaks(hashes, hash_to_check)
hash_password(password)
pwned_api_check(password)
main(file_path)

"""

import sys
import hashlib
import requests


def request_api_data(query_char):
    """
    Returns the API response from https://api.pwnedpasswords.com/range/
    for a given hash keyword
        Parameters:
            query_char (hex): A 5 letter hexadecimal as a partial of a hash key.

         Returns:
            api response data: string format

    """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {response.status_code}, check the api and try again"
        )
    return response


def get_password_leaks(hashes, hash_to_check):
    """
    Returns the number of a times a password has been leaked
        Parameters:
            hashes (list): A list of hashes and number of times they have been leaked
            hash_to_check (hex): The hash of the password to check if it has been pwned.

         Returns:
            count (int): A decimal integer.

    """
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count

    return 0


def hash_password(password):
    """
    Returns the sha1 hash keyword for the password
        Parameters:
            password (string): password

         Returns:
            first5_char (hex): The first 5 hexadecimal characters of the hash key
            tail (hex): The remaining hexadecimal characters of the hash key

    """

    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    return first5_char, tail


def pwned_api_check(password):
    """
    Returns a print argument on whether a given password has been compromised or is safe.
        Parameters:
            password (string): password

         Returns:
            None


    """
    first5_char, tail = hash_password(password)

    response = request_api_data(first5_char)
    count = get_password_leaks(response, tail)
    if count:
        print(f"Your {password} have been pwned {count} times")
    else:
        print(f"Your password is safe!")
    return


def main(file_path):
    """
    Checks if a list of password provided in a file have been compromised on the web.
        Parameters:
            file_path (string): A command line argument with the file_directory including extension.


         Returns:
            None

    """
    with open(file_path, "r") as file:
        passwords = file.readlines()
        for p in passwords:

            pwned_api_check(p.splitlines()[0])

    return


if __name__ == "__main__":

    sys.exit(main(sys.argv[1]))
