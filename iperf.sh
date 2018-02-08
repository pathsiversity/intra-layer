#!/bin/bash
iperf -c 172.1.1.2 -t 10 -P 1&
iperf -c 172.0.0.2 -t 10 -P 1&
exit 0
