#!/bin/bash
screen -dm -S export-squid-stats python export_squid_stats.py --client_address=192.168.4.153
#screen -dm -S export-squid-stats python export_squid_stats.py --client_address=192.168.4.153 --file tests/resources/test_access.log