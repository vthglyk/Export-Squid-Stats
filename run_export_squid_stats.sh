#!/bin/bash
pushd /opt/squid/Export-Squid-Stats
screen -dm -S export-squid-stats python export_squid_stats.py --client_address=192.168.0.202
#screen -dm -S export-squid-stats python export_squid_stats.py --client_address=192.168.4.153 --file tests/resources/test_access.log
