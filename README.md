# PTRStream
> High-performance distributed PTR record scanner with real-time streaming output

![](./.screens/preview.gif)

PTRStream is a fast and efficient PTR record scanner designed for distributed scanning operations. It uses a Linear Congruential Generator *(LCG)* for deterministic IP generation, allowing for easy distribution of work across multiple machines while maintaining pseudo-random ordering.

## Features

- Memory-efficient IP range processing using [GoLCG](https://github.com/acidvegas/golcg)
- Distributed scanning support via sharding
- Real-time NDJSON output for streaming to data pipelines
- Support for both PTR and CNAME records
- Automatic DNS server rotation from public resolvers
- Progress tracking with detailed statistics
- Colorized terminal output

## Installation

```bash
go install github.com/acidvegas/ptrstream@latest
```

## Options
| Flag     | Type     | Default | Description                                |
|----------|----------|---------|--------------------------------------------|
| `-c`     | `int`    | `100`   | Concurrency level                          |
| `-debug` | `bool`   | `false` | Show unsuccessful lookups                  |
| `-dns`   | `string` |         | File containing DNS servers                |
| `-o`     | `string` |         | Path to NDJSON output file                 |
| `-r`     | `int`    | `2`     | Number of retries for failed lookups       |
| `-s`     | `int`    | `0`     | Seed for IP generation *(0 for random)*    |
| `-shard` | `string` |         | Shard specification *(index/total format)* |
| `-t`     | `int`    | `2`     | Timeout for DNS queries                    |


## Usage

```bash
# Basic usage
ptrstream -o output.json

# Use specific DNS servers
ptrstream -dns resolvers.txt -o output.json

# Increase concurrency
ptrstream -c 200 -o output.json

# Distributed scanning (4 machines)
# Machine 1:
ptrstream -shard 1/4 -s 12345 -o shard1.json
# Machine 2:
ptrstream -shard 2/4 -s 12345 -o shard2.json
# Machine 3:
ptrstream -shard 3/4 -s 12345 -o shard3.json
# Machine 4:
ptrstream -shard 4/4 -s 12345 -o shard4.json
```

## Distributed Scanning

PTRStream supports distributed scanning through its sharding system. By using the same seed value across multiple instances with different shard specifications, you can distribute the workload across multiple machines while ensuring:

- No IP address is scanned twice
- Even distribution of work
- Deterministic results
- Pseudo-random scanning patterns

For example, to split the work across 4 machines:
```bash
# Each machine uses the same seed but different shard
ptrstream -shard 1/4 -s 12345  # Machine 1
ptrstream -shard 2/4 -s 12345  # Machine 2
ptrstream -shard 3/4 -s 12345  # Machine 3
ptrstream -shard 4/4 -s 12345  # Machine 4
```

## Real-time Data Pipeline Integration

PTRStream outputs NDJSON *(Newline Delimited JSON)* format, making it perfect for real-time data pipeline integration. Each line contains a complete JSON record with:

- Timestamp
- IP Address
- DNS Server used
- Record Type *(PTR/CNAME)*
- PTR Record
- CNAME Target *(if applicable)*
- TTL Value

Example using named pipe to Elasticsearch:
```bash
# Create a named pipe
mkfifo /tmp/ptrstream

# Start Elasticsearch ingestion in background
cat /tmp/ptrstream | elasticsearch-bulk-import &

# Run PTRStream with pipe output
ptrstream -o /tmp/ptrstream
```

## CNAME Support

PTRStream properly handles CNAME records in PTR responses, providing:
- Detection of CNAME chains
- Original hostname and target tracking
- TTL values for both record types
- Distinct coloring in terminal output
- CNAME statistics tracking

Example NDJSON output:
```json
{"timestamp":"2024-01-05T12:34:56Z","ip_addr":"1.2.3.4","dns_server":"8.8.8.8","ptr_record":"example.com","record_type":"PTR","ttl":3600}
{"timestamp":"2024-01-05T12:34:57Z","ip_addr":"5.6.7.8","dns_server":"1.1.1.1","ptr_record":"original.com","record_type":"CNAME","target":"target.com","ttl":600}
```
---

###### Mirrors: [acid.vegas](https://git.acid.vegas/ptrstream) • [SuperNETs](https://git.supernets.org/acidvegas/ptrstream) • [GitHub](https://github.com/acidvegas/ptrstream) • [GitLab](https://gitlab.com/acidvegas/ptrstream) • [Codeberg](https://codeberg.org/acidvegas/ptrstream)
