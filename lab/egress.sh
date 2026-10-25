#!/usr/bin/env bash
# Shows the runner egress policy holding against raw-packet scans. Needs root and nmap.
#
# Two network namespaces joined by a veth pair: the runner, and a fake LAN holding a target (192.0.2.10),
# an excluded host inside the target range (.12), an off-scope host (.30), and the API (.2:8443).
# Counters on the LAN side record what actually arrived.
set -euo pipefail
cd "$(dirname "$0")"

runner=pen15-lab-runner
lan=pen15-lab-lan
cleanup() { ip netns del "$runner" 2>/dev/null || true; ip netns del "$lan" 2>/dev/null || true; }
trap cleanup EXIT
cleanup

ip netns add "$runner"
ip netns add "$lan"
ip link add runner0 netns "$runner" type veth peer name lan0 netns "$lan"
ip -n "$runner" addr add 192.0.2.100/24 dev runner0
for address in 192.0.2.2 192.0.2.10 192.0.2.12 192.0.2.30; do
	ip -n "$lan" addr add "$address/24" dev lan0
done
ip -n "$runner" link set runner0 up
ip -n "$lan" link set lan0 up

ip netns exec "$lan" nft -f - <<'NFT'
table netdev lab {
	counter target {}
	counter excluded {}
	counter offscope {}
	counter api_allowed {}
	counter api_other {}
	chain ingress {
		type filter hook ingress device lan0 priority 0;
		ip daddr 192.0.2.10 counter name target
		arp daddr ip 192.0.2.10 counter name target
		ip daddr 192.0.2.12 counter name excluded
		arp daddr ip 192.0.2.12 counter name excluded
		ip daddr 192.0.2.30 counter name offscope
		arp daddr ip 192.0.2.30 counter name offscope
		ip daddr 192.0.2.2 tcp dport 8443 counter name api_allowed
		ip daddr 192.0.2.2 tcp dport != 8443 counter name api_other
		ip daddr 192.0.2.2 ip protocol != tcp counter name api_other
	}
}
NFT

cat ../deploy/runner-egress.nft scope.nft | ip netns exec "$runner" nft -D runner_if=runner0 -f -

scan() { ip netns exec "$runner" nmap -n -Pn --max-retries 0 --host-timeout 20s "$@" >/dev/null 2>&1; }
hosts=(192.0.2.10 192.0.2.12 192.0.2.30 192.0.2.2)
scan -sS --send-eth -p 22,80,8443 "${hosts[@]}"
scan -sS --send-ip -p 22,80,8443 "${hosts[@]}"
scan -sU -p 53,161,1900 "${hosts[@]}"
scan -sn -PR -PE "${hosts[@]}"
ip netns exec "$runner" ping -c1 -W1 192.0.2.30 >/dev/null 2>&1 || true

packets() { ip netns exec "$lan" nft list counter netdev lab "$1" | awk '/packets/ { print $2 }'; }
fail=0
expect() {
	local name=$1 condition=$2 count
	count=$(packets "$name")
	if (( count $condition )); then
		echo "ok   $name: $count packets"
	else
		echo "FAIL $name: $count packets, expected $condition"
		fail=1
	fi
}
expect target "> 0"
expect api_allowed "> 0"
expect excluded "== 0"
expect offscope "== 0"
expect api_other "== 0"
exit "$fail"
