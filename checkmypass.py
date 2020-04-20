import requests
import hashlib
import sys

raw_password = "password123"
sha1_password = "cbfdac6008f9cab4083784cbd1874f76618d2a97"
k_anon_password = sha1_password[0:5]
# print(k_anon_password)

def request_api_data(query_chars):
    url = "https://api.pwnedpasswords.com/range/" + query_chars
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check api and try again")
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    # convert password to sha1 hash
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_chars, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_chars)
    count = get_password_leaks_count(response, tail)
    return count


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} for found {count} times. You should change password")
        else:
            print(f"good {password}")
    return "done"

if __name__=="__main__":
    sys.exit(main(sys.argv[1:]))
