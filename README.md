# vibe-dns (TESTING - USE AT OWN RISK)

My little filtering DNS server in Python vibed together using Google Gemini and Claude.

This was an excersise to see how things work. Not too bad actually...

See `full_config.yaml` for more information.

Run it with `python3 server.py --config <config-yaml-file>` (Python 3.14+).

It's always DNS.


=======

# Features:

**Smart, policy-driven DNS filtering engine**
The system lets you build tailored DNS behaviour for different users, devices, and networks. You can mix blocking, allow-listing, categorization, and upstream selection per group.

**Client-aware filtering**
It identifies clients by IP, subnet, or MAC (eithe local/native and/or viaa EDNS0), or on which ip-address and/or port their queries come in, so you can assign different rules to kids, guests, IoT gear, or whole LAN segments.

**Time-based controls**
Schedules allow policies to activate only during certain hours — like “bedtime”, “school hours”, or work-time restrictions — and automatically return to normal afterwards.

**Domain categorization**
A built-in categorization layer can classify domains (ads, adult, social media, gambling, etc.) with confidence scoring. Policies can block categories selectively, per client group.

**Flexible policy engine**
Policies decide what to do with a query:

* Block, filter, sinkhole, or allow
* Use specific upstream resolvers
* Enforce TTL rules
* Rewrite or collapse CNAMEs
* Strip unwanted metadata

Everything is composable, so groups can inherit schedules + policies cleanly.

**Multiple blocklist sources**
It can pull lists from remote or local sources (hosts files, custom lists, category lists). These combine with the policy engine to determine the final behaviour.

**Upstream resolver intelligence**
Supports multiple resolver groups with balancing, failover, and health checks. It can probe latency, choose the fastest path, or stick to a group depending on your strategy.

**Caching with prefetch**
There’s an internal response cache, including stale-serve and prefetch logic to keep latency low and reduce upstream load. Entries close to expiry can be refreshed proactively.

**Rate-limiting & abuse protection**
The server can identify abusive clients or subnets, slow them down, or drop excess traffic — useful for noisy IoT or small DoS-style bursts.

**Response shaping**
It can rewrite or minimize DNS responses: round-robin answers, TTL clamping, removing extra sections, collapsing chains — handy for privacy, consistency or load-balancing.

**Startup safety**
It can check upstream health before going live, and fall back to bootstrap resolvers if needed.

