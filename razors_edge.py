#!/usr/bin/env python3

""" razors_edge.py - Show unique DNS requests within a specified time period.

    by Daniel Roberson (@dmfroberson)                              June/2018


To make this work:

pip3 install mmh3 scapy


TODO:
    - syslog
    - cli input sanitizations
    - "learning timeout" to avoid printing stuff like your monitoring services
      connecting to you or being queried.
"""

import os
import mmh3
import time
import argparse
from math import ceil, log
from scapy.all import *


class TimingBloomFilter():
    """TimingBloomFilter class - Implements time-based bloom filters.

    Attributes:
        size (int) - size of the filter.
        hashcount (int) - ideal number of hashes per filter element.
        filter (list) - list of elements. Value is None or a timestamp.
        timeout (int) - seconds that elements should be valid.
    """
    def __init__(self, expected, fp_rate, timeout):
        self.size = self.ideal_size(expected, fp_rate)
        self.hashcount = self.ideal_hashcount(self.size, expected)
        self.filter = [None] * self.size
        self.timeout = timeout

    @staticmethod
    def ideal_size(expected, fp_rate):
        """ideal_size() - Calculate ideal filter size.

        Args:
            expected (int) - Expected number of elements to add to the filter.
            fp_rate (int) - Desired false positive rate. Ex: 0.01 for 99.99%

        Returns:
            Ideal size (int)
        """
        return int(-(expected * log(fp_rate)) / (log(2) ** 2))

    @staticmethod
    def ideal_hashcount(size, expected):
        """ideal_hashcount() - Calculate ideal number of hashes per element.

        Args:
            size (int) - Size of the filter.
            expected (int) - Expected number of elements.

        Returns:
            Ideal number of hashes to use per element.
        """
        return int((size / int(expected)) * log(2))

    def add(self, element):
        """add() - Add an element to the filter.

        Args:
            element (str) - Element to add to the filter.

        Returns:
            Nothing.
        """
        current_time = time.time()
        for seed in range(self.hashcount):
            result = mmh3.hash(str(element), seed) % self.size
            self.filter[result] = current_time

    def lookup(self, element):
        """lookup() - Check if an element exists in the filter. This also
                      reaps expired elements if they are found.

        Args:
            element (str) - Element to check for.

        Returns:
            True if element is likely to exist in the filter.
            False if the element definitely does not exist in the filter.
        """
        current_time = time.time()
        result = True
        for seed in range(self.hashcount):
            index = mmh3.hash(str(element), seed) % self.size
            if self.filter[index] is None:
                result = False
            elif current_time - self.filter[index] > self.timeout:
                self.filter[result] = None
                result = False
        return result


def dns_sniff(pkt):
    """dns_sniff() - Check DNS queries against a timed filter.

    Args:
        pkt - Scapy data structure containing packet data.

    Returns:
        Nothing.
    """
    if IP in pkt:
        if pkt.getlayer(DNS).qr == 0:
            source_addr = str(pkt[IP].src)
            dest_addr = str(pkt[IP].dst)
            query = pkt.getlayer(DNS).qd.qname.decode("ascii")

            element_str = source_addr + ":" + dest_addr + ":" + query

            if dns_filter.lookup(element_str):
                # Element exists. Update the filter with our current timestamp.
                dns_filter.add(element_str)
            else:
                # Element doesn't exist. Add it to the filter and generate an
                # alert. This just prints data to stdout rather than doing any
                # useful alerting.
                dns_filter.add(element_str)
                print("[%s] %s -> %s -- %s" % \
                      (time.ctime(time.time()), source_addr, dest_addr, query))


def main():
    """main() - program's entry point.
    """
    global dns_filter

    description = "razors_edge.py -- by Daniel Roberson @dmfroberson"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-s",
        "--size",
        default=500000,
        type=int,
        help="expected number of elements")
    parser.add_argument(
        "-a",
        "--accuracy",
        default=0.01,
        type=int,
        help="desired false positive rate. Default: 0.01")
    parser.add_argument(
        "-t",
        "--timeout",
        default=24*60*60,
        type=int,
        help="seconds that a filter element remains valid. Default: 86400")
    parser.add_argument(
        "-i",
        "--interface",
        default="eth0",
        help="interface to monitor")
    args = parser.parse_args()

    dns_filter = TimingBloomFilter(args.size, args.accuracy, args.timeout)

    print("[+] razors_edge.py starting.")
    print(" - Interface: %s" % args.interface)
    print(" - # of elements: %d" % args.size)
    print(" - Timeout: %d seconds" % args.timeout)
    print(" - Accuracy: %s%%" % str(100 - args.accuracy))

    # Start the DNS sniffer
    try:
        sniff(iface=args.interface,
            filter="udp dst port 53",
            prn=dns_sniff,
            store=0)
    except PermissionError:
        print("[-] Can't open %s for sniffing. Are you root?" % args.interface)
        exit(os.EX_USAGE)


if __name__ == "__main__":
    main()

