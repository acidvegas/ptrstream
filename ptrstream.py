#/usr/bin/env python
# ptrstream - developed by acidvegas in python (https://git.acid.vegas/ptrstream)

import argparse
import asyncio
import ipaddress
import os
import random
import time
import urllib.request

try:
	import aiodns
except ImportError:
	raise ImportError('missing required \'aiodns\' library (pip install aiodns)')

# Do not store these in the results file
bad_hosts = ['localhost','undefined.hostname.localhost','unknown']

# Colors
class colors:
	ip        = '\033[35m'
	ip_match  = '\033[96m' # IP address mfound within PTR record
	ptr       = '\033[93m'
	red       = '\033[31m' # .gov or .mil indicator
	invalid   = '\033[90m'
	reset     = '\033[0m'
	grey      = '\033[90m'


def get_dns_servers() -> list:
	'''Get a list of DNS servers to use for lookups.'''
	source = urllib.request.urlopen('https://public-dns.info/nameservers.txt')
	results = source.read().decode().split('\n')
	return [server for server in results if ':' not in server]


async def rdns(semaphore: asyncio.Semaphore, ip_address: str, resolver: aiodns.DNSResolver):
	'''
	Perform a reverse DNS lookup on an IP address.

	:param semaphore: The semaphore to use for concurrency.
	:param ip_address: The IP address to perform a reverse DNS lookup on.
	'''
	async with semaphore:
		reverse_name = ipaddress.ip_address(ip_address).reverse_pointer
		try:
			answer = await resolver.query(reverse_name, 'PTR')
			if answer.name not in bad_hosts and answer.name != ip_address and answer.name != reverse_name:
				return ip_address, answer.name, True
			else:
				return ip_address, answer.name, False
		except aiodns.error.DNSError as e:
			if e.args[0] == aiodns.error.ARES_ENOTFOUND:
				return ip_address, f'{colors.red}No rDNS found{colors.reset}', False
			elif e.args[0] == aiodns.error.ARES_ETIMEOUT:
				return ip_address, f'{colors.red}DNS query timed out{colors.reset}', False
			else:
				return ip_address, f'{colors.red}DNS error{colors.grey} ({e.args[1]}){colors.reset}', False
		except Exception as e:
			return ip_address, f'{colors.red}Unknown error{colors.grey} ({str(e)}){colors.reset}', False


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


def fancy_print(ip: str, result: str):
	'''
	Print the IP address and PTR record in a fancy way.

	:param ip: The IP address.
	:param result: The PTR record.
	'''
	if result in ('127.0.0.1', 'localhost','undefined.hostname.localhost','unknown'):
		print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.grey}-> {result}{colors.reset}')
	else:
		if ip in result:
			result = result.replace(ip, f'{colors.ip_match}{ip}{colors.ptr}')
		elif (daship := ip.replace('.', '-')) in result:
			result = result.replace(daship, f'{colors.ip_match}{daship}{colors.ptr}')
		elif (revip := '.'.join(ip.split('.')[::-1])) in result:
			result = result.replace(revip, f'{colors.ip_match}{revip}{colors.ptr}')
		elif (revip := '.'.join(ip.split('.')[::-1]).replace('.','-')) in result:
			result = result.replace(revip, f'{colors.ip_match}{revip}{colors.ptr}')
	print(f'{colors.ip}{ip.ljust(15)}{colors.reset} {colors.grey}->{colors.reset} {colors.ptr}{result}{colors.reset}')


async def main(args: argparse.Namespace):
	'''
	Generate random IPs and perform reverse DNS lookups.

	:param args: The command-line arguments.
	'''
	if args.resolvers:
		if os.path.exists(args.resolvers):
			with open(args.resolvers) as file:
				dns_resolvers = [item.strip() for item in file.read().splitlines()]
		else:
			raise FileNotFoundError(f'could not find file \'{args.resolvers}\'')
	else:
		dns_resolvers = get_dns_servers()
	dns_resolvers = random.shuffle(dns_resolvers)

	resolver = aiodns.DNSResolver(nameservers=dns_resolvers, timeout=args.timeout, tries=args.retries, rotate=True)
	semaphore = asyncio.Semaphore(args.concurrency)

	tasks = []
	results_cache = []

	seed = random.randint(10**9, 10**10 - 1) if not args.seed else args.seed
	ip_generator = rig(seed)

	for ip in ip_generator:
		if len(tasks) < args.concurrency:
			task = asyncio.create_task(rdns(semaphore, ip, resolver))
			tasks.append(task)
		else:
			done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
			tasks = list(pending)
			for task in done:
				ip, result, success = task.result()
				if result:
					fancy_print(ip, result)
					if success:
						results_cache.append(f'{ip}:{result}')
				if len(results_cache) >= 1000:
					stamp = time.strftime('%Y%m%d')
					with open(f'ptr_{stamp}_{seed}.txt', 'a') as file:
						file.writelines(f"{record}\n" for record in results_cache)
					results_cache = []



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Perform asynchronous reverse DNS lookups.')
	parser.add_argument('-c', '--concurrency', type=int, default=100, help='Control the speed of lookups.')
	parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout for DNS lookups.')
	parser.add_argument('-r', '--resolvers', type=str, help='File containing DNS servers to use for lookups.')
	parser.add_argument('-rt', '--retries', type=int, default=3, help='Number of times to retry a DNS lookup.')
	parser.add_argument('-s', '--seed', type=int, help='Seed to use for random number generator.')
	args = parser.parse_args()

	asyncio.run(main(args))
