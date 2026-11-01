# When the client (the runner) may be the problem

The `vsphere-triage` tools see vCenter and the ESXi hosts, never the machine
that calls them. A runner (the automation host, a CI worker, the orchestrator's
container) with a network or resource problem gets the same `SSLEOFError`,
resets and timeouts as a vCenter at its limit. The tools can only **clear the
server side**; proving the runner needs the runner's own evidence. Load this
file when the server side came back clean.

## Signs it is the runner

| Sign | Points at |
| --- | --- |
| At the error time the server side is clean: the session count well under the cap (`check_vcenters`), no appliance restart (`vcenter_appliance_health`), no hostd or proxy restart (`search_host_logs`), no load spike (`correlate_hosts`) | something outside vCenter and the hosts |
| Only this runner fails; other clients of the same vCenter (the vSphere Client, this server, other automation) work at the same moment | the runner or its network path |
| The error is the **first call after a quiet period**, and a retry works | an idle connection dropped in the path (a firewall, NAT or load balancer idle timeout) and reused by the client's connection pool |
| The failures grow with the runner's own concurrency, on every host and vCenter alike | the runner's connection table, ports, file descriptors or CPU |
| Failures only to the ESXi hosts' IPs, never to vCenter (or the reverse) | the path to those addresses: a firewall rule, a proxy, an MTU black hole |
| A monitoring "Tools error" on a VM that vCenter shows with Tools running | the runner's own status call failed, not Tools (see below) |

## How a runner problem becomes a "Tools error"

A runner's network cannot break Tools inside a VM. It can make the runner
*report* a Tools error. The runner learns about Tools only through vCenter:
it polls the VM's Tools status (or waits for guest operations to be ready),
and it runs guest operations (a command, a file transfer) that go through
Tools. When those calls fail because the runner's connection dropped, its
wait times out or the guest operation raises, and the orchestrator labels
that a Tools error: "Tools not running", "Tools not ready", "guest operations
unavailable", or a timeout waiting for Tools.

To tell which it was, check the VM's own record, not the runner's:

- now: `diagnose_vm` or `scan` (Tools running, heartbeat green, not flagged
  `guest_ops_not_ready`);
- at the error time: `read_vm_log` with a pattern such as `tools|guestinfo`,
  since `vmware.log` records when Tools came up and stopped, and
  `get_boot_timeline` for when Tools first came up after the boot.

Tools up throughout while the runner said otherwise: the error was the
runner's call, and the cause is on the runner or its path.

## Before connecting

The runner is not reached through the `vsphere-triage` server. Reach it from
your own shell, and only with a person's say-so:

1. **Ask first** (**stop and ask**): which runner, the account and the key or
   credentials to use. Never guess a host, never use credentials you were not
   given, and say exactly what you will run.
2. Connect with `ssh user@runner '<command>'`, or, from a script, paramiko
   (`SSHClient`, its `connect`, then `exec_command` for each command below,
   reading stdout and stderr). Any SSH client will do; a container runner may
   need `kubectl exec` or `docker exec` instead.
3. **Read only.** Run the commands below and nothing else. Never change a
   setting (`sysctl -w`, `ulimit`, firewall rules), restart or kill a process,
   install a package, or edit a file. A fix you find goes in the verdict for a
   person.
4. Run the checks **while the runner is failing** if you can: most of them
   show the state now, not the state at the error.

## The checks

Replace `<vc>` with the vCenter's address and `<esx>` with an ESXi host IP from
a failing transfer URL.

| Check | Command | What it means |
| --- | --- | --- |
| Clock and load | `date -u; uptime` | a runner clock off by minutes breaks TLS and certificate checks; a load far above its CPU count starves handshakes |
| Kernel messages | `dmesg -T 2>/dev/null \| grep -iE 'conntrack\|table full\|oom\|killed process' \| tail -20` | `nf_conntrack: table full` drops connections (resets and EOFs); an OOM kill takes the automation's connections with it |
| Connection table | `cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max` (and `conntrack -S` where installed) | a count near the max is dropping new connections; a rising `drop` or `insert_failed` in `conntrack -S` confirms it |
| Sockets | `ss -s` and `ss -tan state time-wait \| wc -l` | thousands of TIME_WAIT sockets against the port range below mean a client that opens a connection per request |
| Port range | `cat /proc/sys/net/ipv4/ip_local_port_range` | the ports a runner can use per destination; TIME_WAIT near this size runs it out ("Cannot assign requested address") |
| Connections to 443 | `ss -tanp '( dport = :443 )' \| awk '{print $1}' \| sort \| uniq -c` | how many connections the runner holds to vCenter and the hosts, and in what state; many in SYN-SENT means nothing answers |
| File descriptors | `cat /proc/<pid>/limits \| grep -i 'open files'; ls /proc/<pid>/fd \| wc -l` (the automation's pid) | at the limit, new sockets fail ("Too many open files"), which cascades into failed calls |
| Container CPU throttling | `cat /sys/fs/cgroup/cpu.stat` (cgroup v2) | a growing `nr_throttled` / `throttled_usec` means the container is held back, and handshakes time out under it |
| Proxy in the path | `env \| grep -i proxy` (in the automation's environment) | an `HTTPS_PROXY` that the vSphere calls or the host downloads go through can cut or inspect TLS |
| Route and MTU | `ip route get <esx>; ip link` then `ping -M do -s 1472 -c 3 <esx>` | a ping that fails at 1472 bytes but works smaller is an MTU black hole: handshakes stall or are cut |
| TLS from the runner | `openssl s_client -connect <vc>:443 -brief </dev/null` and the same for `<esx>:443` | reachability and the certificate from the runner's own path, the check `check_host_tls` cannot make from here |
| A short probe loop | `for i in $(seq 20); do timeout 10 openssl s_client -connect <esx>:443 -brief </dev/null >/dev/null 2>&1 && echo ok \|\| echo FAIL; sleep 3; done` | intermittent failures from the runner while this server sees none |

## The decisive test: a capture

Who closed the connection settles it. With a person's OK, capture only the
connection closes on 443 to the vCenter and the host, for a bounded time:

```
timeout 300 tcpdump -i any -nn -s 96 -c 20000 -w /tmp/eof.pcap \
  'tcp port 443 and (host <vc> or host <esx>) and (tcp[tcpflags] & (tcp-rst|tcp-fin) != 0)'
```

`tcpdump` needs root; TLS payloads are encrypted, and `-s 96` keeps only the
headers anyway. Then `tcpdump -nn -r /tmp/eof.pcap | head -50`:

- a **reset or FIN from the server's address** at the failure: the server (or
  something in front of it) closed it, so go back to the server side;
- **no close from the server** while the runner errors: the runner gave up
  (a timeout) or something between them dropped or reset the connection;
- a capture at the vCenter or host end too, with a reset there that the
  server never sent: a middlebox in the path.

## Ask about the code

Two client-side causes are in the automation, not the machine; ask the person:

- **One pyVmomi connection shared across threads** gives random SSL errors
  under concurrency. Each worker thread should use its own session (or a lock).
- **Long-lived pooled connections with no keep-alive** are dropped by an idle
  timeout in the path, and the first call after a pause fails. A keep-alive
  shorter than that timeout, or a reconnect-and-retry on the first failure,
  fixes it.

## The verdict

Name the runner-side cause only with runner-side evidence (a check above, or
the capture). With only "the server side is clean", say the runner or the path
is the remaining suspect, list the checks above as the next step, and leave
them for the person to run or approve.
