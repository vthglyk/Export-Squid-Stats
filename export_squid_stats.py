"""
- Cache hit ratio (total)
This can be used for measurements and the GUI as well.
    - Total (across all incoming requests) = cacheHttpHits / cacheProtoClientHttpRequests
    - Peering (ratio of peering queries leading to a hit) = cacheClientHttpHits.ip / cacheClientHttpRequests
    - Local (ration of the local clients)

- Cache Hits
This is the absolute number of hits, could be used to show some kind of counter on the GUI, as the cache hits increase.
    - Total (across all incoming requests) = cacheHttpHits
    - Peering (ratio of peering queries leading to a hit) = cacheClientHttpHits.ip
    - Local hits

- Download times
Would be useful if we could show this somehow, though it comes from the clients, not a vCache.
Perhaps we could instead use the "response time" which is recorded in the access.logs
("how much time it took to process the request. The timer starts when Squid receives the HTTP request and
stops when the response has been fully delivered.")
Check: Service Timing Statistics

- CPU / RAM utilization
Perhaps coming from the prometheus module (?)
CPU coming from this, RAM from node_exporter

- Traffic load
I assume prometheus supports something like this. It can be used for the security scenario (increase of traffic
leads to alert and some policy-based action)
    - On the link to the switch
    - On the peering link (interface of each peering vCache)
From node exporter (there might be a problem because the interface to the clients and the server is the same

- Request rate (per sec)
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
    args = parser.parse_args()

    global peer_address
    global client_address

    peer_address = args.peer_address
    client_address = args.client_address
    log_level = args.loglevel
    period = args.period

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
    node_cpu_gauge = Gauge('node_cpu', 'Advertises the cpu usage', ['cpu', 'mode'])

    # Todo:

    while True:

        time.sleep(period)

        # output = check_output(["snmpwalk", "-v", "1", "-c", "public", "-m", "SQUID-MIB", "-Cc",
        #                        "localhost:3401", "squid"])

        # cache_client_icp_hits_gauge.set(extract_metric(output, "cacheClientIcpHits"))
        # cache_client_icp_requests_gauge.set(extract_metric(output, "cacheClientIcpRequests"))
        # cache_client_http_hits_gauge.set(extract_metric(output, "cacheClientHttpHits"))
        # cache_client_http_requests_gauge.set(extract_metric(output, "cacheClientHttpRequests"))
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
