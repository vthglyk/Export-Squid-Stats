"""
- Cache hit ratio (total): DONE
This can be used for measurements and the GUI as well.
    - Total (across all incoming requests) =
      (cacheClientHttpHits.client_ip + sibling_hits from logs) / cacheClientHttpRequests.client_ip
    - Peering (ratio of peering queries leading to a hit) = sibling_hits from logs / cacheClientHttpRequests.client_ip
    - Local (ratio of the local clients) =
      cacheClientHttpHits.client_ip / cacheClientHttpRequests.client_ip

- Cache Hits: DONE
This is the absolute number of hits, could be used to show some kind of counter on the GUI, as the cache hits increase.
    - Total (across all incoming requests) = cacheClientHttpHits.client_ip + sibling_hits from logs
    - Peering (ratio of peering queries leading to a hit) = sibling_hits from logs
    - Local hits = cacheClientHttpHits.client_ip

- Download times
Would be useful if we could show this somehow, though it comes from the clients, not a vCache.
Perhaps we could instead use the "response time" which is recorded in the access.logs
("how much time it took to process the request. The timer starts when Squid receives the HTTP request and
stops when the response has been fully delivered.")
Check: Service Timing Statistics (NOT WORKING)
  - mean local hits
  - mean peering hits
  - mean misses

- CPU / RAM utilization: DONE
Perhaps coming from the prometheus module (?)
CPU coming from this, RAM from node_exporter

- Traffic load: IN PROMETHEUS
I assume prometheus supports something like this. It can be used for the security scenario (increase of traffic
leads to alert and some policy-based action)
    - On the link to the switch
    - On the peering link (interface of each peering vCache)
From node exporter (there might be a problem because the interface to the clients and the server is the same

- Request rate (per sec): NOT DONE
Can be used for the security scenario as well. Not absolutely necessary but could assist in the demo
i.e., "we see requests increasing, we see CPU utilization increasing on the peer, we see some alert, an action,
we see that requests keep coming but the peering link is no longer active, so CPU utilization dropped"
    - From Clients
    - From Peering vCache
For this we will probably need some persistence to hold previous values of request rates
"""

import time
import argparse
import logging
import re

from subprocess import check_output
from prometheus_client import start_http_server, Gauge

peer_address = None
client_address = None


def parse_logs(log_file, last_pos):
    sibling_hits_string = "SIBLING_HIT"
    sibling_hits = 0

    with open(log_file, 'r') as f:
        f.seek(last_pos)
        new_data = f.readlines()
        last_pos = f.tell()

        for i in new_data:
            parts = i.split()

            if len(parts) >= 8 and sibling_hits_string in parts[8]:
                sibling_hits += 1
                logging.info("Found SIBLING_HIT (sibling hits in this round = {})".format(sibling_hits))

    return [sibling_hits, last_pos]


def extract_metric(output, metric):
    if metric == "cacheClientIcpHits" or metric == "cacheClientIcpRequests":
        help = output.split(metric + '.' + str(peer_address))[-1].split(":")
    elif metric == "cacheClientHttpHits" or metric == "cacheClientHttpRequests":
        help = output.split(metric + '.' + str(client_address))[-1].split(":")
    else:
        help = output.split(metric)[-1].split(":")

    if help[1] == '':
        return 0
    else:
        return int(help[1].split("\n")[0])


def main():

    parser = argparse.ArgumentParser(description='Export cache metrics to prometheus')
    parser.add_argument('--peer_address', '-p', required=True,
                        help='the ip address of the cache peer (REQUIRED)')
    parser.add_argument('--client_address', '-c', required=True,
                        help='the ip address of the client (REQUIRED)')
    parser.add_argument('--loglevel', '-l', default="WARNING",
                        help='the maximum number of rules to be installed (default: "WARNING"')
    parser.add_argument('--period', '-t', default=1, type=int,
                        help='the reporting period in seconds (default: 1)')
    parser.add_argument('--file', default="/var/log/squid/access.log",
                        help='the squid access.log file (default: "/var/log/squid/access.log")')
    args = parser.parse_args()

    global peer_address
    global client_address

    peer_address = args.peer_address
    client_address = args.client_address
    log_level = args.loglevel
    squid_log_file = args.file
    period = args.period

    sibling_hits = 0
    last_pos = 0

    log_level_numeric = getattr(logging, log_level.upper(), None)
    if not isinstance(log_level_numeric, int):
        raise ValueError('Invalid log level: %s' % log_level)
    logging.basicConfig(level=log_level_numeric)

    start_http_server(9101)
    # Generate some requests.

    cache_client_icp_hits_gauge = Gauge('cache_client_icp_hits',
                                        'Advertises the value of the metric "cacheClientIcpHits" of squid')
    cache_client_icp_requests_gauge = Gauge('cache_client_icp_requests',
                                            'Advertises the value of the metric "cacheClientIcpRequests" of squid')
    cache_client_http_hits_gauge = Gauge('cache_client_http_hits',
                                         'Advertises the value of the metric "cacheClientHttpHits" of squid')
    cache_client_http_requests_gauge = Gauge('cache_client_http_requests',
                                             'Advertises the value of the metric "cacheClientHttpRequests" of squid')
    cache_request_hit_ratio1_gauge = Gauge('cache_request_hit_ratio_1',
                                           'Advertises the value of the metric "cacheRequestHitRatio.1" of squid')
    cache_request_byte_ratio1_gauge = Gauge('cache_request_byte_ratio_1',
                                            'Advertises the value of the metric "cacheRequestByteRatio.1" of squid')
    cache_request_hit_ratio5_gauge = Gauge('cache_request_hit_ratio_5',
                                           'Advertises the value of the metric "cacheRequestHitRatio.5" of squid')
    cache_request_byte_ratio5_gauge = Gauge('cache_request_byte_ratio_5',
                                            'Advertises the value of the metric "cacheRequestByteRatio.5" of squid')
    cache_request_hit_ratio60_gauge = Gauge('cache_request_hit_ratio_60',
                                            'Advertises the value of the metric "cacheRequestHitRatio.60" of squid')
    cache_request_byte_ratio60_gauge = Gauge('cache_request_byte_ratio_60',
                                             'Advertises the value of the metric "cacheRequestByteRatio.60" of squid')
    cache_cpu_usage_gauge = Gauge('cache_cpu_usage',
                                  'Advertises the value of the metric "cacheCpuUsage" of squid')
    cache_num_obj_count_gauge = Gauge('cache_num_obj_count',
                                      'Advertises the value of the metric "cacheNumObjCount" of squid')
    cache_proto_client_http_requests_gauge = Gauge('cache_proto_client_http_requests',
                                                   ('Advertises the value of the metric '
                                                    '"cacheProtoClientHttpRequests" of squid'))
    cache_http_hits_gauge = Gauge('cache_http_hits',
                                  'Advertises the value of the metric "cacheHttpHits" of squid')
    cache_sibling_hits_gauge = Gauge('sibling_hits',
                                     'Advertises the value of the hits in the peering cache')
    cache_total_hits_gauge = Gauge('total_hits',
                                   'Advertises the value of the total hits in the vCache (local + peering)')
    cache_local_hit_ratio_gauge = Gauge('local_hit_ratio',
                                        'Hit ratio due to local hits')
    cache_peering_hit_ratio_gauge = Gauge('peering_hit_ratio',
                                          'Hit ratio due to peering hits')
    cache_total_hit_ratio_gauge = Gauge('total_hit_ratio',
                                        'Total cache hit ratio (local + peering)')
    node_cpu_gauge = Gauge('node_cpu', 'Advertises the cpu usage', ['cpu', 'mode'])

    # Todo:

    while True:

        time.sleep(period)

        [new_sibling_hits, last_pos] = parse_logs(squid_log_file, last_pos)
        sibling_hits += new_sibling_hits
        logging.info("Total number of sibling hits = {})".format(sibling_hits))

        cache_client_http_hits = extract_metric(output, "cacheClientHttpHits")
        cache_client_http_requests = extract_metric(output, "cacheClientHttpRequests")

        # output = check_output(["snmpwalk", "-v", "1", "-c", "public", "-m", "SQUID-MIB", "-Cc",
        #                        "localhost:3401", "squid"])

        # cache_client_icp_hits_gauge.set(extract_metric(output, "cacheClientIcpHits"))
        # cache_client_icp_requests_gauge.set(extract_metric(output, "cacheClientIcpRequests"))
        # cache_client_http_hits_gauge.set(cache_client_http_hits)
        # cache_client_http_requests_gauge.set(cache_client_http_requests)
        # cache_request_hit_ratio1_gauge.set(extract_metric(output, "cacheRequestHitRatio.1"))
        # cache_request_byte_ratio1_gauge.set(extract_metric(output, "cacheRequestByteRatio.1"))
        # cache_request_hit_ratio5_gauge.set(extract_metric(output, "cacheRequestHitRatio.5"))
        # cache_request_byte_ratio5_gauge.set(extract_metric(output, "cacheRequestByteRatio.5"))
        # cache_request_hit_ratio60_gauge.set(extract_metric(output, "cacheRequestHitRatio.60"))
        # cache_request_byte_ratio60_gauge.set(extract_metric(output, "cacheRequestByteRatio.60"))
        # cache_cpu_usage_gauge.set(extract_metric(output, "cacheCpuUsage"))
        # cache_num_obj_count_gauge.set(extract_metric(output, "cacheNumObjCount"))
        # cache_proto_client_http_requests_gauge.set(extract_metric(output, "cacheProtoClientHttpRequests"))
        # cache_http_hits_gauge.set(extract_metric(output, "cacheHttpHits"))
        # cache_sibling_hits_gauge.set(sibling_hits)
        # cache_total_hits_gauge.set(sibling_hits + cache_client_http_hits)
        # cache_local_hit_ratio_gauge.set(cache_client_http_hits / cache_client_http_requests)
        # cache_peering_hit_ratio_gauge.set(sibling_hits / cache_client_http_requests)
        # cache_total_hit_ratio_gauge.set((cache_client_http_hits + sibling_hits) / cache_client_http_requests)

        output = check_output(["top", "-b", "-n1"])
        logging.debug("output = " + str(output))

        help = output.split('Cpu(s):')[-1].split('\n')[0].split(' ')
        logging.debug("help = " + str(help))

        cpu_modes = []
        for i in help:
            if re.match("[0-9,]", i):
                cpu_modes.append(float(i.replace(',', '.')))
        logging.debug("cpu_modes = " + str(cpu_modes))

        node_cpu_gauge.labels(cpu='cpu0', mode='us').set(cpu_modes[0])
        node_cpu_gauge.labels(cpu='cpu0', mode='sy').set(cpu_modes[1])
        node_cpu_gauge.labels(cpu='cpu0', mode='ni').set(cpu_modes[2])
        node_cpu_gauge.labels(cpu='cpu0', mode='id').set(cpu_modes[3])
        node_cpu_gauge.labels(cpu='cpu0', mode='wa').set(cpu_modes[4])
        node_cpu_gauge.labels(cpu='cpu0', mode='hi').set(cpu_modes[5])
        node_cpu_gauge.labels(cpu='cpu0', mode='si').set(cpu_modes[6])
        node_cpu_gauge.labels(cpu='cpu0', mode='st').set(cpu_modes[7])


if __name__ == '__main__':
    # Start up the server to expose the metrics.
    main()
