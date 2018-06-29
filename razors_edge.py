#!/usr/bin/env python3

""" razors_edge.py - Show unique DNS requests within a specified time period.

    by Daniel Roberson (@dmfroberson)                              June/2018


To make this work:

pip3 install mmh3 scapy
"""

import mmh3
import time
from math import ceil, log, log2
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


# Create a filter with 500000 expected elements, 99.99% accuracy, and expire
# elements after 1 hour. The size is very high for most hosts, but for
# demonstration, it works well enough (you're not likely to make 500k unique
# DNS requests in an hour). Sniffing DNS requests for the desired time limit
# before deploying this would give a better idea of a value to use here.
dns_filter = TimingBloomFilter(500000, 0.01, 1*60*60)


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
                print("%s -> %s -- %s" % (source_addr, dest_addr, query))


# Start the DNS sniffer. Probably will need to change the interface name here.
sniff(iface="ens160", filter="udp dst port 53", prn=dns_sniff, store=0)

