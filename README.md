# bixsn

An **authorized SNMP audit tool**. `bixsn` sweeps hosts you own for weak SNMP
exposure — guessable community strings (v1/v2c), enumerable USM users (v3),
live-agent discovery, and read-write access — and records everything to an
append-only audit log.

It is **fail-closed**: it refuses to run unless you explicitly declare the
target range as yours. Use it only against infrastructure you are authorized to
test.

## Features

- **Community brute (v1/v2c)** — tries a wordlist of community strings.
- **SNMPv3 USM user enumeration** — detects which usernames an agent recognizes.
- **Live-agent discovery** — probes for a responding v3 agent and extracts its engineID.
- **Read-write proof (`--test-write`)** — proves RW access via an idempotent
  write-back of `sysLocation` (writes the same value it read).
- **Mandatory authorization scope** — every target must fall inside a declared range.
- **Append-only audit log** — timestamped record of each run.

## Requirements

- A C++17 compiler (g++ 12+ / clang 15+)
- CMake ≥ 3.16
- Net-SNMP development files (`libsnmp-dev`)

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential cmake libsnmp-dev
```

## Build

```bash
cmake -B build
cmake --build build
ctest --test-dir build        # runs cidr_test and scope_test
```

The binary is produced at `build/bixsn`.

## Usage

A scope is **required** — the tool will not run without one.

```
./build/bixsn [options] <targets>
```

`<targets>` is a comma-separated list of CIDRs, ranges, or IPs
(e.g. `10.0.0.0/24,10.0.1.1-50`).

### Declaring scope

| Option | Description |
|--------|-------------|
| `--scope FILE` | scope file with CIDRs/ranges, one per line |
| `--i-own-this-range SPEC` | add an inline scope rule |

Any target outside the declared scope is skipped.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--version v1\|v2c\|v3` | `v2c` | SNMP protocol |
| `--community-file FILE` | `data/community-strings.txt` | community wordlist |
| `--v3-user-file FILE` | `data/v3-users.txt` | v3 username wordlist |
| `--port N` | `161` | UDP port |
| `--threads N` | `16` | concurrency |
| `--timeout MS` | `1000` | per-request timeout |
| `--retries N` | `1` | per-request retries |
| `--delay MS` | — | global minimum interval between requests (rate limit) |
| `--test-write` | off | prove RW via idempotent write-back (**writes to the target**) |
| `--audit-log FILE` | `bixsn-audit.log` | audit log path |

## Examples

```bash
# Community brute over a /24 you own (v2c)
./build/bixsn --i-own-this-range 10.0.0.0/24 10.0.0.0/24

# Enumerate SNMPv3 users on a single host
./build/bixsn --version v3 --i-own-this-range 10.7.0.55 10.7.0.55

# Gentle sweep: fewer threads, rate-limited, longer timeout
./build/bixsn --i-own-this-range 10.0.0.0/24 \
  --threads 8 --delay 50 --timeout 1500 10.0.0.0/24

# Scope from a file
./build/bixsn --scope scope.txt 10.0.0.1-50
```

## Interpreting output

```
== 10.7.0.55:161 ==
  engineID: 800063a280303fbb4bf37900000001
  [INFO] SNMPv3 agent alive — engineID discovered

summary: 1 host(s) with SNMP open, 1 finding(s), 0 critical.
```

- `[INFO]` — informational (e.g. a live agent): no exploitable issue by itself.
- `[MEDIUM]` — e.g. a recognized v3 username, or a guessed community.
- `[CRITICAL]` — e.g. a community that accepts a SET (RW access).

The engineID prefix encodes the vendor's enterprise number; `800063a2` is
Net-SNMP (25506).

## ⚠️ Warnings

- **`--test-write` writes to the device.** It performs an idempotent write-back
  of `sysLocation` (re-writes the value it just read), but it is still a real
  SET. Only use it with explicit permission.
- Enumeration and brute-forcing can generate load on network equipment. Use
  `--delay` and lower `--threads` against production gear.
- The audit log may contain data about real targets — keep it out of version
  control (it is already in `.gitignore`).

## Project layout

```
src/
  core/        SNMP session wrapper, result types, OIDs
  net/         CIDR/range parsing, thread pool
  discovery/   live-agent / engineID probe
  brute/       community brute (v1/v2c), v3 USM enumeration
  collect/     system-group walk
  report/      text reporter
  safety/      authorization scope, audit log
  main.cpp     CLI entry point
data/          default wordlists
tests/         cidr_test, scope_test
```

## License

Released under the [MIT License](LICENSE). For authorized security testing only.
