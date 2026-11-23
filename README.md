<div align="center">

# PTRStream

**Reverse DNS for the whole IPv4 internet, every address exactly once.**

[![Release](https://img.shields.io/github/v/release/acidvegas/ptrstream?style=flat-square&color=success)](https://github.com/acidvegas/ptrstream/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/acidvegas/ptrstream?style=flat-square&logo=go&logoColor=white)](./go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/acidvegas/ptrstream?style=flat-square)](https://goreportcard.com/report/github.com/acidvegas/ptrstream)
[![License](https://img.shields.io/github/license/acidvegas/ptrstream?style=flat-square&color=blue)](./LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/acidvegas/ptrstream?style=flat-square)](https://github.com/acidvegas/ptrstream/commits)
[![Stars](https://img.shields.io/github/stars/acidvegas/ptrstream?style=flat-square&color=yellow)](https://github.com/acidvegas/ptrstream/stargazers)
<br>
![IPv4 coverage](https://img.shields.io/badge/IPv4_coverage-100%25-00d7ff?style=flat-square)
![Output](https://img.shields.io/badge/output-NDJSON-8a2be2?style=flat-square)
![Sharding](https://img.shields.io/badge/sharding-n%2Ftotal-success?style=flat-square)
![Resume](https://img.shields.io/badge/resume-exact-success?style=flat-square)

![](./.screens/preview.gif)

</div>

PTRStream looks up the PTR record of every IPv4 address through public recursive resolvers and streams the answers as NDJSON. It walks the address space with a counter whose octets are reversed *(the same order as massdns's `ptr.py`)*, so every address is queried exactly once, consecutive queries land in different /8s, and the work splits cleanly across as many machines as you like.

## Contents

- [Highlights](#highlights)
- [Performance](#performance)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Options](#options)
- [How it works](#how-it-works)
- [Output](#output)
- [Running 24/7](#running-247)
- [Excluding ranges](#excluding-ranges)
- [Stats line](#stats-line)
- [Debug mode](#debug-mode)

## Highlights

|                      |                                                                                                                                      |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Complete**         | All 4,294,967,296 IPv4 addresses, each exactly once, in octet-reversed order                                                         |
| **Fast**             | Batched queries from 4 long-lived UDP sockets *(sendmmsg / recvmmsg)*, a timeout wheel and an optional query rate cap                |
| **Careful**          | Answers are only accepted from the resolver that was asked, for the question that was asked. Truncated answers are repeated over TCP |
| **Resilient**        | Retries on the next resolver, failing resolvers are benched for 10 minutes, and the resolver list refreshes every 24 hours           |
| **Distributed**      | `-shard n/total` gives each machine its own slice of the address space, with no coordinator                                          |
| **Resumable**        | A state file records exactly how far the scan got, so a restart never skips or loses an address                                      |
| **Complete answers** | Every PTR name for an address is kept, and RFC 2317 classless delegations are followed                                               |
| **Two interfaces**   | A live colorized TUI, or plain NDJSON on stdout for pipelines                                                                        |

## Performance

A full sweep of IPv4 on a single 1 vCPU / 512MB VPS:

| Metric                        | Result                                                   |
|-------------------------------|----------------------------------------------------------|
| Time for all 4.29B addresses  | 6 days 1 hour                                            |
| Addresses per second          | median 8,195 *(fastest hour 9,407)*                      |
| Answers per second            | median 2,386                                             |
| Addresses with a PTR or CNAME | 1.24B *(about 29%)*                                      |
| Resolvers                     | ~12,000 public resolvers, ~6,000 active at a time        |
| Settings                      | `-rate 12000 -c 50000`, 0 packets dropped by the scanner |

More machines scale it close to linearly, each one taking a shard.

## Installation

Prebuilt static binaries for Linux *(amd64, arm64, arm)*, macOS *(amd64, arm64)* and FreeBSD *(amd64)* are on the [releases page](https://github.com/acidvegas/ptrstream/releases/latest), each with `reserved.txt` and a `SHA256SUMS` file to check them against.

With Go 1.26 or newer:

```bash
go install github.com/acidvegas/ptrstream@latest
```

Or build from source:

```bash
git clone https://github.com/acidvegas/ptrstream.git
cd ptrstream
go build -o ptrstream .
```

## Quick start

```bash
# Live TUI, results saved to a file
ptrstream -o ptr.ndjson

# NDJSON to stdout for a pipeline, capped at 12,000 queries per second
ptrstream -j -rate 12000 | your-ingest-tool

# Your own resolvers instead of the public list
ptrstream -dns resolvers.txt -o ptr.ndjson

# A 24/7 scanner that survives restarts and skips non-public ranges
ptrstream -j -l -state ptr.state -exclude reserved.txt -o ptr.ndjson

# Split the work over 4 machines
ptrstream -shard 1/4 -o shard1.ndjson   # machine 1
ptrstream -shard 2/4 -o shard2.ndjson   # machine 2
ptrstream -shard 3/4 -o shard3.ndjson   # machine 3
ptrstream -shard 4/4 -o shard4.ndjson   # machine 4
```

## Options

| Flag              | Type       | Default | Description                                                                                                                    |
|-------------------|------------|---------|--------------------------------------------------------------------------------------------------------------------------------|
| `-c`              | `int`      | `10000` | Max lookups in flight                                                                                                          |
| `-r`              | `int`      | `2`     | Retries on the next resolver for timeouts, SERVFAIL and REFUSED                                                                |
| `-t`              | `duration` | `2s`    | Timeout for each DNS query                                                                                                     |
| `-rate`           | `int`      | `0`     | Max queries per second, retries included *(0 for unlimited)*                                                                   |
| `-dns`            | `string`   |         | File of DNS servers, one per line *(default: the [trickest](https://github.com/trickest/resolvers) list, refreshed every 24h)* |
| `-shard`          | `string`   |         | Shard to scan, as `n/total`                                                                                                    |
| `-state`          | `string`   |         | State file to resume from and save progress to                                                                                 |
| `-l`              | `bool`     | `false` | Start the next round when the shard is finished                                                                                |
| `-exclude`        | `string`   |         | File of IPv4 CIDRs or IPs to skip *(one per line, `#` comments)*                                                               |
| `-o`              | `string`   |         | NDJSON output file *(appended to)*                                                                                             |
| `-j`              | `bool`     | `false` | NDJSON to stdout instead of the TUI                                                                                            |
| `-debug`          | `bool`     | `false` | Also output failed lookups *(see [Debug mode](#debug-mode))*                                                                   |
| `-stats-interval` | `duration` | `10m`   | How often to log a stats line to stderr with `-j` *(0 to turn off)*                                                            |

## How it works

**Scan order.** A counter runs from 0 to 2³² − 1 and each value is turned into an address by reversing its 4 bytes: 1 becomes `1.0.0.0`, 2 becomes `2.0.0.0`, 256 becomes `0.1.0.0`. Every address comes out exactly once, back to back queries are in different /8s, and the addresses of any one /24 are spread over the whole run instead of arriving together.

**Sharding.** `-shard n/total` takes the n-th contiguous slice of the counter. Because of the byte reversal, every shard still covers the whole internet evenly. Shards never overlap and together cover every address, so machines need no coordination.

**Resolvers.** Queries rotate across the resolver list. A resolver that fails 20 times in a row *(timeouts, SERVFAIL, REFUSED, garbage)* is benched for 10 minutes. Failed lookups are retried on the next resolver up to `-r` times.

## Output

Results are NDJSON, one record per line, on stdout with `-j` and appended to the `-o` file:

| Field         | Description                                                                                                                   |
|---------------|-------------------------------------------------------------------------------------------------------------------------------|
| `@timestamp`  | Time of the answer *(RFC 3339)*                                                                                               |
| `ip`          | IP address                                                                                                                    |
| `nameserver`  | Resolver that answered                                                                                                        |
| `record`      | All PTR names for the address, or the `FAIL.` error name *(left out for a CNAME with no PTR behind it)*                       |
| `record_type` | `PTR`, `CNAME` or `ERR`                                                                                                       |
| `cname`       | CNAME target in the answer *(the RFC 2317 delegation a PTR was reached through, or the whole answer for `record_type` CNAME)* |
| `ttl`         | TTL of the answer                                                                                                             |

Classless reverse delegation *(RFC 2317)* answers with a CNAME followed by the PTR it points to. That is recorded as a `PTR` with the CNAME target in `cname`. A CNAME with no PTR behind it is recorded as `CNAME` with no `record`, so `cname` always means the CNAME target:

```json
{"@timestamp":"2026-11-16T02:17:37-05:00","ip":"195.53.95.8","nameserver":"1.1.1.1","record":["8.red-195-53-95.customer.static.ccgg.telefonica.net"],"record_type":"PTR","cname":"8.0.95.53.195.in-addr.arpa","ttl":86400}
{"@timestamp":"2026-11-16T02:17:37-05:00","ip":"151.41.96.70","nameserver":"8.8.8.8","record_type":"CNAME","cname":"41.151.in-addr.arpa","ttl":3600}
{"@timestamp":"2026-11-16T02:17:37-05:00","ip":"70.48.177.180","nameserver":"1.1.1.1","record":["bras-base-wtbyon9417w-grc-11-70-48-177-180.dsl.bell.ca","bras-base-toroon01zb4-grc-37-70-48-177-180.dsl.bell.ca"],"record_type":"PTR","ttl":86400}
```

## Running 24/7

`-l` starts the next round when the shard is finished and `-state` survives restarts:

```bash
ptrstream -j -l -shard 1/4 -state shard1.state -exclude reserved.txt -o shard1.ndjson
```

The state file is one line, written every 10 seconds and on SIGINT / SIGTERM:

```
shard=1/4 round=3 next=1834567890
```

`next` is the lowest position that still has an unfinished lookup *(tracked in blocks of 4,096 addresses)*, and output is flushed before the file is written, so a restart never skips an address. Lookups that finished after that position are queried again, usually a few seconds of work. A state file for a different shard is refused. Starting on a state file whose round is finished begins the next round, with or without `-l`.

## Excluding ranges

Nothing is skipped unless a file is passed with `-exclude`. [`reserved.txt`](./reserved.txt) lists the IPv4 ranges that are not on the public internet *(RFC 6890 special purpose, multicast and the old class E space)*. Resolvers answer those from their own local zones, mostly with `localhost`, so the results are not real data. A full sweep gets about 64,000 of these answers.

## Stats line

With `-j`, every `-stats-interval` a line goes to stderr with the rates over that interval and what every finished address ended with, as a share of all addresses finished in it *(the shares add up to 100%, the numbers below are only an example)*:

```
stats round=1 progress=1.006% next=43216647 elapsed=10m0s ips/s=7950 ptr/s=2350 queries/s=12000 retries/s=4050 ptr=29.6% nxdomain=38.2% servfail=6.1% refused=1.9% noptr=19.7% timeout=4.5% other=0.0% lookups=4769985 queries=7200000 resolvers=5857/12123
```

`-rate` caps `queries/s`, retries included, so `ips/s` is lower when many lookups need retries. The TUI shows the same numbers live, so the line is off without `-j`.

## Debug mode

With `-debug`, failed lookups are shown and output too, using CAIDA-style error names under `.in-addr.arpa`:

```
        1.2.3.4 │ 8.8.8.8         │  ERR  │         │ FAIL.TIMEOUT.in-addr.arpa
        5.6.7.8 │ 1.1.1.1         │  ERR  │         │ FAIL.SERVER-FAILURE.in-addr.arpa
     9.10.11.12 │ 8.8.4.4         │  ERR  │         │ FAIL.NXDOMAIN.in-addr.arpa
```

| Error name                         | Meaning                                     |
|------------------------------------|---------------------------------------------|
| `FAIL.TIMEOUT.in-addr.arpa`        | No answer in time, on every attempt         |
| `FAIL.SERVER-FAILURE.in-addr.arpa` | SERVFAIL on every attempt                   |
| `FAIL.NXDOMAIN.in-addr.arpa`       | No reverse zone exists for the address      |
| `FAIL.REFUSED.in-addr.arpa`        | Refused on every attempt                    |
| `FAIL.NO-PTR-RECORD.in-addr.arpa`  | NOERROR with no PTR record *(NODATA)*       |
| `FAIL.TRUNCATED.in-addr.arpa`      | Truncated over UDP and the TCP retry failed |

In the NDJSON they look like this:

```json
{"@timestamp":"2024-01-05T12:34:56Z","ip":"1.2.3.4","nameserver":"8.8.8.8","record":["FAIL.TIMEOUT.in-addr.arpa"],"record_type":"ERR","ttl":0}
```
