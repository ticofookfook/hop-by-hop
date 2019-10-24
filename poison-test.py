import requests
import random
import string

letters = string.ascii_lowercase

with open('domains.txt') as fp:
    for domain in fp:
        if '*' not in domain:
            headers = {
                'Connection': 'close, X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto',
            }
            params1 = {
                'cb': ''.join(random.choice(letters) for i in range(10))
            }
            params2 = {
                'cb': ''.join(random.choice(letters) for i in range(10))
            }
            if 'https://' not in domain and 'http://' not in domain:
                domain = 'https://%s' % domain.strip()

            # try a normal request and one with our hop-by-hop headers (and a cache buster)
            try:
                req1 = requests.get(domain, params=params1, allow_redirects=False)
                req2 = requests.get(domain, headers=headers, params=params2, allow_redirects=False)
            except requests.exceptions.ConnectionError as e:
                pass
            except requests.exceptions.SSLError as e:
                pass
            
            # if HbH headers cause a different response code, try and see if we poisoned cache
            if req1.status_code != req2.status_code:
                print '%s %s %s %s' % (domain, params2, req1.status_code, req2.status_code)
                try:
                    req3 = requests.get(domain, params=params2, allow_redirects=False)
                except requests.exceptions.ConnectionError as e:
                    pass
                except requests.exceptions.SSLError as e:
                    pass
                if req3.status_code == req2.status_code:
                    print '%s/?cb=%s %s, poisoned?' % (domain, req3.status_code, params2['cb'])
