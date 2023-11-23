#/usr/bin/env python
# ptrstream - developed by acidvegas in python (https://git.acid.vegas/ptrstream)

import argparse
import asyncio
import ipaddress
import random
import time
import urllib.request

try:
	import aiodns
except ImportError:
	raise ImportError('missing required \'aiodns\' library (pip install aiodns)')

# Colors
class colors:
	ip = '\033[35m'
	ip_match = '\033[96m'
	ptr = '\033[93m'
	spooky = '\033[31m'
	invalid = '\033[90m'
	reset = '\033[0m'
	separator = '\033[90m'

dns_resolvers = []

def get_dns_servers() -> list:
	'''Get a list of DNS servers to use for lookups.'''
	source = urllib.request.urlopen('https://public-dns.info/nameservers.txt')
	results = source.read().decode().split('\n')
	return [server for server in results if ':' not in server]

async def rdns(semaphore: asyncio.Semaphore, ip_address: str, resolver: aiodns.DNSResolver):
	'''
	Perform a reverse DNS lookup on an IP address.

	:param ip_address: The IP address to lookup.
	:param resolver: The DNS resolver to use for lookups.
	:param semaphore: A semaphore to limit the number of concurrent lookups.
	'''
	async with semaphore:
		reverse_name = ipaddress.ip_address(ip_address).reverse_pointer
		try:
			answer = await resolver.query(reverse_name, 'PTR')
			return ip_address, answer.name
		except:
			return ip_address, None

def rig(seed: int) -> str:
	'''
	Random IP generator.

	:param seed: The seed to use for the random number generator.
	'''
	max_value = 256**4
	random.seed(seed)
	for _ in range(max_value):
		shuffled_index = random.randint(0, max_value - 1)
		ip = ipaddress.ip_address(shuffled_index)
		yield str(ip)

async def main():
	'''Generate random IPs and perform reverse DNS lookups.'''
	semaphore = asyncio.Semaphore(args.concurrency)
	tasks = []
	results_cache = []

	global dns_resolvers
	if not dns_resolvers:
		dns_resolvers = [aiodns.DNSResolver(nameservers=[server], rotate=False, timeout=args.timeout) for server in get_dns_servers()[:args.concurrency]]

	seed = random.randint(10**9, 10**10 - 1)
	ip_generator = rig(seed)

	for ip in ip_generator:
		if len(tasks) < args.concurrency:
			resolver = random.choice(dns_resolvers)
			task = asyncio.create_task(rdns(semaphore, ip, resolver))
			tasks.append(task)
		else:
			done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
			tasks = list(pending)
			for task in done:
				ip, result = task.result()
				if result:
					if result in ('127.0.0.1', 'localhost'):
						print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.separator}-> {result}{colors.reset}')
					elif ip in result:
						result = result.replace(ip, f'{colors.ip_match}{ip}{colors.ptr}')
					elif (daship := ip.replace('.', '-')) in result:
						result = result.replace(daship, f'{colors.ip_match}{daship}{colors.ptr}')
						print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.separator}->{colors.reset} {colors.ptr}{result}{colors.reset}')
					elif (revip := '.'.join(ip.split('.')[::-1])) in result:
						result = result.replace(revip, f'{colors.ip_match}{revip}{colors.ptr}')
						print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.separator}->{colors.reset} {colors.ptr}{result}{colors.reset}')
					elif result.endswith('.gov') or result.endswith('.mil'):
						result = result.replace('.gov', f'{colors.spooky}.gov{colors.reset}')
						result = result.replace('.mil', f'{colors.spooky}.gov{colors.reset}')
						print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.separator}->{colors.reset} {colors.ptr}{result}{colors.reset}')
					elif '.gov.' in result or '.mil.' in result:
						result = result.replace('.gov.', f'{colors.spooky}.gov.{colors.ptr}')
						result = result.replace('.mil.', f'{colors.spooky}.mil.{colors.ptr}')
						print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.separator}->{colors.reset} {colors.ptr}{result}{colors.reset}')
					else:
						print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.separator}->{colors.reset} {colors.ptr}{result}{colors.reset}')

					results_cache.append(f'{ip}:{result}')
				if len(results_cache) >= 1000:
					stamp = time.strftime('%Y%m%d')
					with open(f'ptr_{stamp}_{seed}.txt', 'a') as file:
						file.writelines(f"{record}\n" for record in results_cache)
					results_cache = []



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Perform asynchronous reverse DNS lookups.')
	parser.add_argument('-c', '--concurrency', type=int, default=50, help='Control the speed of lookups.')
	parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout for DNS lookups.')
	parser.add_argument('-r', '--resolvers', type=str, help='File containing DNS servers to use for lookups.')
	args = parser.parse_args()

	asyncio.run(main())
