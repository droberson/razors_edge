# Razor's Edge

Monitor for unique DNS queries within a speficied timeframe. Useful for
filtering out noise in DNS traffic.

## Requirements

Requires mmh3 and scapy:

```
pip3 install mmh3 scapy
```

## usage

Sniff enp150 for unique lookups within the hour with 0.01% error rate:
```
./razors_edge.py -i enp150 -t 3600 -a 0.01
```
