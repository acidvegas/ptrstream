#/usr/bin/env python
# arpa stream - developed by acidvegas in python (https://git.acid.vegas/ptrstream)

'''
I have no idea where we are going with this, but I'm sure it'll be fun...
'''

import argparse
import concurrent.futures
import random

try:
    import dns.resolver
except ImportError:
    raise ImportError('missing required \'dnspython\' library (pip install dnspython)')


class colors:
    axfr     = '\033[34m'
    error    = '\033[31m'
    success  = '\033[32m'
    ns_query = '\033[33m'
    ns_zone  = '\033[36m'
    reset    = '\033[0m'


def genip() -> str:
    '''Generate a random IP address with 1 to 4 octets.'''
    num_octets = random.randint(1, 4)
    ip_parts = [str(random.randint(0, 255)) for _ in range(num_octets)]
    return '.'.join(ip_parts)


def query_ns_records(ip: str) -> list:
    '''
    Query NS records for a given IP.
    
    :param ip: The IP address to query NS records for.
    '''
    try:
        ns_records = [str(record.target)[:-1] for record in dns.resolver.resolve(f'{ip}.in-addr.arpa', 'NS')]
        if ns_records:
            print(f'{colors.ns_zone}Queried NS records for {ip}: {ns_records}{colors.reset}')
        return ns_records
    except Exception as e:
        print(f'{colors.error}Error querying NS records for {ip}: {e}{colors.reset}')
        return []


def resolve_ns_to_ip(ns_hostname: str) -> list:
    '''
    Resolve NS hostname to IP.
    
    :param ns_hostname: The NS hostname to resolve.
    '''
    try:
        ns_ips = [ip.address for ip in dns.resolver.resolve(ns_hostname, 'A')]
        if ns_ips:
            print(f'{colors.ns_query}Resolved NS hostname {ns_hostname} to IPs: {ns_ips}{colors.reset}')
        return ns_ips
    except Exception as e:
        print(f'{colors.error}Error resolving NS {ns_hostname}: {e}{colors.reset}')
        return []


def axfr_check(ip: str, ns_ip: str):
    '''
    Perform AXFR check on a specific nameserver IP.
    
    :param ip: The IP address to perform the AXFR check on.
    :param ns_ip: The nameserver IP to perform the AXFR check on.
    '''
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ns_ip]
    try:
        if resolver.resolve(f'{ip}.in-addr.arpa', 'AXFR'):
            print(f'{colors.success}[SUCCESS]{colors.reset} AXFR on {ns_ip} for {ip}.in-addr.arpa')
            return True
    except Exception as e:
        print(f'{colors.error}[FAIL]{colors.reset} AXFR on {ns_ip} for {ip}.in-addr.arpa - Error: {e}')
        return False


def process_ip(ip: str):
    '''
    Process each IP: Fetch NS records and perform AXFR check.
    
    :param ip: The IP address to process.
    '''
    for ns_hostname in query_ns_records(ip):
        for ns_ip in resolve_ns_to_ip(ns_hostname):
            if axfr_check(ip, ns_ip):
                return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS AXFR Check Script')
    parser.add_argument('--concurrency', type=int, default=100, help='Number of concurrent workers')
    args = parser.parse_args()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(process_ip, genip()): ip for ip in range(args.concurrency)}
        while True:
            done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                future.result()  # We don't need to store the result as it's already printed
                futures[executor.submit(process_ip, genip())] = genip()
            futures = {future: ip for future, ip in futures.items() if future not in done}