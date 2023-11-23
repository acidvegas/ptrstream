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


def get_dns_servers() -> list:
	'''Get a list of DNS servers to use for lookups.'''
	source = urllib.request.urlopen('https://public-dns.info/nameservers.txt')
	results = source.read().decode().split('\n')
	return [server for server in results if ':' not in server]


async def rdns(semaphore: asyncio.Semaphore, ip_address: str, custom_dns_server: str):
	'''
	Perform a reverse DNS lookup on an IP address.

	:param ip_address: The IP address to lookup.
	:param custom_dns_server: The DNS server to use for lookups.
	:param semaphore: A semaphore to limit the number of concurrent lookups.
	:param timeout: The timeout for the lookup.
	'''
	async with semaphore:
		resolver = aiodns.DNSResolver(nameservers=[custom_dns_server], rotate=False, timeout=args.timeout)
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

	if args.resolvers:
		with open(args.resolvers) as file:
			dns_servers = [server.strip() for server in file.readlines()]

	while True:
		if not args.resolvers:
			dns_servers = []
			while not dns_servers:
				try:
					dns_servers = get_dns_servers()
				except:
					time.sleep(300)

		seed = random.randint(10**9, 10**10 - 1)
		ip_generator = rig(seed)

		for ip in ip_generator:
			if len(tasks) < args.concurrency:
				dns = random.choice(dns_servers)
				task = asyncio.create_task(rdns(semaphore, ip, dns))
				tasks.append(task)
			else:
				done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
				tasks = list(pending)
				for task in done:
					ip, result = task.result()
					if result:
						if result in ('127.0.0.1','localhost'):
							print(f'\033[35m{ip.ljust(15)}\033[0m \033[90m-> {result}\033[0m')
						elif ip in result:
							result = result.replace(ip, f'\033[96m{ip}\033[93m')
						elif (daship := ip.replace('.', '-')) in result:
							result = result.replace(daship, f'\033[96m{daship}\033[93m')
							print(f'\033[35m{ip.ljust(15)}\033[0m \033[90m->\033[0m \033[93m{result}\033[0m')
						elif (revip := '.'.join(ip.split('.')[::-1])) in result:
							result = result.replace(revip, f'\033[96m{revip}\033[93m')
							print(f'\033[35m{ip.ljust(15)}\033[0m \033[90m->\033[0m \033[93m{result}\033[0m')
						elif result.endswith('.gov') or result.endswith('.mil'):
							result = result.replace('.gov', f'\033[31m.gov\033[0m')
							result = result.replace('.mil', f'\033[31m.gov\033[0m')
							print(f'\033[35m{ip.ljust(15)}\033[0m \033[90m->\033[0m \033[93m{result}\033[0m')
						elif '.gov.' in result or '.mil.' in result:
							result = result.replace('.gov.', f'\033[31m.gov.\033[0m')
							result = result.replace('.mil.', f'\033[31m.mil.\033[0m')
							print(f'\033[35m{ip.ljust(15)}\033[0m \033[90m->\033[0m \033[93m{result}\033[0m')
						else:
							scary = ('.gov')
							print(f'\033[35m{ip.ljust(15)}\033[0m \033[90m->\033[0m \033[93m{result}\033[0m')
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
