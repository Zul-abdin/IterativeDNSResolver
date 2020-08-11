# Zain Ul-Abdin 2020
from resolver_background import DnsResolver
import threading
from socket import *
import socket
import argparse
from sys import argv
import time
from helper_funcs import DNSQuery
import random

# All Type and Class Definitions for both RRs and Queries:

# Types of RRs
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_DNAME = 39
TYPE_OPT = 41

# Types of Classes of RRs
CLASS_IN = 1

# Query Types
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_DNAME = 39
QTYPE_OPT = 41
QTYPE_AXFR = 252
QTYPE_MAILB = 253
QTYPE_MAILA = 254
QTYPE_STAR = 255

# Query Classes
QCLASS_IN = 1
QCLASS_STAR = 255

# Response Codes (RCODEs)
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# SBELT
s_belt = ["91.239.100.100", "198.101.242.72", "199.9.14.201", "202.12.27.33"]

# cache is a dict which maps {OWNER/NAME -> full RR answers as taken from DNSQuery(...).answers}
# check cache for all answers of name = s_name, else return none
# Cache Question: 0 TTL latency from check??

# Say we have an RR of type NS, where {NAME = google.com, RDATA = ns1.google.com}
# Does that RR go into the cache['google.com'] or cache['ns1.google.com'], or do name servers just not go in cache?


class MyResolver(DnsResolver):
    def __init__(self, port):
        super().__init__(port)
        self.port = port
        # define variables and locks you will need here
        self.cache_lock = threading.Lock()
        self.cache = {}

    def check_cache(self, q_name, q_type, q_class):
        s_name = q_name.decode('ASCII')
        result = []
        if s_name in self.cache:
            for tup in self.cache[s_name]:
                if time.time() - tup[0]['TTL'] > tup[1]:
                    self.cache[s_name].remove(tup)
                    continue
                if q_type == QTYPE_STAR or (tup[0]['TYPE'] == q_type and tup[0]['CLASS'] == q_class):
                    upd_tup = tup[0]
                    upd_tup['TTL'] = int((time.time() + tup[0]['TTL']) - tup[1])
                    result.append(upd_tup)
        return result

    # Adds an answer to cache
    def update_cache(self, answer):
        with self.cache_lock:
            if not answer['NAME'].decode('ASCII') in self.cache:
                self.cache[answer['NAME'].decode('ASCII')] = [[answer, time.time()]]
            else:
                for rr in self.cache[answer['NAME'].decode('ASCII')]:
                    if rr[0]['NAME'] == answer['NAME'] and rr[0]['TYPE'] == answer['TYPE'] and rr[0]['CLASS'] == answer['CLASS'] and rr[0]['RDATA'] == answer['RDATA']:
                        return
                self.cache[answer['NAME'].decode('ASCII')].append([answer, time.time()])

    def format_query(self, s_name, q_type, q_class):
        q = DNSQuery()
        q.header['ID'] = random.randint(0, 65535)
        q.question['NAME'] = s_name
        q.question['QTYPE'] = q_type
        q.question['QCLASS'] = q_class
        q.header['QDCOUNT'] = 1
        return q.to_bytes()

    def dname_substitution(self, q_type, q_name, owner, target):
        if owner == q_name:
            if q_type == QTYPE_DNAME:
                return q_name
            else:
                return None

        if ('.' + owner.decode('ASCII')) not in q_name.decode('ASCII'):
            return None

        labels = q_name.decode('ASCII').replace(owner.decode('ASCII'), target.decode('ASCII')).split('.')

        # Check labels for overflow
        for label in labels:
            if len(label.encode('ASCII')) > 63:
                return None

        ans = q_name.decode('ASCII').replace(owner.decode('ASCII'), target.decode('ASCII')).encode('ASCII')

        # Check for domain name overflow
        if len(ans) > 255:
            return None

        return ans

    # Returns a list of RRs of type NS ranked best to worst based on OWNER/NAME compared to SNAME
    # Example:
    # 1) check if www.google.com. is in SLIST, then check if www.google.com. is contained as a substring in SLIST
    # 2) check if google.com. is in SLIST,     then check if google.com. is contained as a substring in SLIST
    # 3) check if com. is in SLIST,            then check if com. is contained as a substring in SLIST
    # 4) check if . is in SLIST,               then check if . is contained as a substring in SLIST
    # 5) return a random server

    def best_server(self, q_name, answers):

        s_name = q_name.decode('ASCII')

        # servers is list of NS in answers
        servers = []
        for server in answers:
            if server['TYPE'] == TYPE_NS:
                servers.append(server)

        result = []
        sub_query = s_name
        num_labels = s_name.count('.') + 1

        if sub_query[0] != '.':
            sub_query = '.' + sub_query

        for i in range(num_labels):
            for server in servers:
                if sub_query[1:] == server['NAME'].decode('ASCII'):
                    result.append(server)
                    servers.remove(server)
            for server in servers:
                if sub_query[1:] in server['NAME'].decode('ASCII'):
                    result.append(server)
                    servers.remove(server)
            sub_query = sub_query[sub_query.find('.', 1):]

        result = result + servers

        # Returning None indicates to resolver to fallback onto SBELT
        if len(result) == 0:
            result = None

        return result

    def handle_response(self, dns_response, serv_sock, sorted_s_list, query):

        # Check response errors

        if dns_response.header['RCODE'] == RCODE_NXDOMAIN:
            return dns_response.answers, RCODE_NXDOMAIN

        q = DNSQuery(query)

        q_name = q.question['NAME']
        q_type = q.question['QTYPE']
        q_class = q.question['QCLASS']

        # Check for answer
        if any((server['TYPE'] == q_type and server['CLASS'] == q_class and server['NAME'] == q_name)
               for server in dns_response.answers):
            ans_rr = []
            for server in dns_response.answers:
                if server['TTL'] > 0:
                    self.update_cache(server)
                if server['TYPE'] == q_type and server['CLASS'] == q_class and server['NAME'] == q_name:
                    ans_rr.append(server)
            return ans_rr, 0

        # If no valid answer
        for server in dns_response.answers:
            # Store in cache
            if server['TTL'] > 0:
                self.update_cache(server)

        for server in dns_response.answers:
            # Handle CNAME response
            if server['TYPE'] == TYPE_CNAME:
                s_name = server['RDATA'][0]

                # restart search with CNAME as SNAME
                c_name_ans, r_code = self.rec_resolve(serv_sock, [], self.format_query(s_name, q_type, q_class))
                return ([server] + c_name_ans), r_code

            if server['TYPE'] == TYPE_SOA:
                return [server], 0

            # Handle DNAME response
            if server['TYPE'] == TYPE_DNAME:
                s_name = self.dname_substitution(q_type, q_name, server['NAME'], server['RDATA'])
                if s_name is not None:
                    # restart search with DNAME substitute as SNAME
                    return self.rec_resolve(serv_sock, [], self.format_query(s_name, q_type, q_class))

            # Add Name Servers to s_list
            if server['TYPE'] == TYPE_NS:
                sorted_s_list.append(server)

        # restart with some name servers in new list
        return self.rec_resolve(serv_sock, sorted_s_list, query)

        # The actual DNS Resolver algorithm
        # PARAMS
        # serv_sock: a pre-defined internet socket to send and recieve data
        # s_list: a list of full RRs of possible servers to jump to
        # root_servers: hard coded server RRs in case SLIST goes dry
        # query: the query to resolve
        # s_name: the SNAME, the domain name you are trying to get info for
        # q_type: the type of

    def rec_resolve(self, serv_sock, s_list, query):

        q = DNSQuery(query)

        q_name = q.question['NAME']
        q_type = q.question['QTYPE']
        q_class = q.question['QCLASS']

        # Step 1 - Check cache
        # if it is in cache, return all answers
        cached_ans = self.check_cache(q_name, q_type, q_class)
        if len(cached_ans) != 0:
            return cached_ans, 0

        # Step 2 - Find optimal server in SLIST
        # sorted_s_list is a list of ranked server domain names
        sorted_s_list = self.best_server(q_name, s_list)

        # generate ips for each server in sorted_s_list

        if sorted_s_list is not None:

            name_s_list = []
            for rr in sorted_s_list:
                name_s_list.append(rr['RDATA'][0].decode('ASCII'))

            print("Finding IPs for: " + str(name_s_list))
            # new_ips contains full RRs of Type A of corresponding servers in sorted_s_list
            new_ips = []
            # get IPs of new s_list
            for server in sorted_s_list:
                # Appends RR from rec_resolve of a fresh query ('starts over')
                new_ips.append(self.rec_resolve(serv_sock, [], self.format_query(server['RDATA'][0], QTYPE_A, QCLASS_IN))[0])
                print("Found IP for: " + server['RDATA'][0].decode('ASCII'))

            # Step 3: Query servers until one sends a response
            for server_ip in new_ips:
                # server_ip is a list of answers which may include CNAME, so look for the Type A rr first
                rr = None
                for rr in server_ip:
                    if rr['TYPE'] == TYPE_A:
                        break

                if rr is not None:
                    try:
                        serv_sock.sendto(query, (socket.inet_ntoa(rr['RDATA'][0]), 53))
                        response = serv_sock.recv(4096)

                        dns_response = DNSQuery(response)

                        # Step 4: Analyze response
                        print("Going to " + rr['NAME'].decode('ASCII'))
                        return self.handle_response(dns_response, serv_sock, [], query)

                    except timeout:
                        del sorted_s_list[new_ips.index(server_ip)]

        # No name servers found -> Fallback to SBELT
        for server in s_belt:
            try:
                server_ip = server
                serv_sock.sendto(query, (server_ip, 53))
                response = serv_sock.recv(4096)
                return self.handle_response(DNSQuery(response), serv_sock, [], query)

            except timeout:
                continue

    def get_dns_response(self, query):

        # input: A query and any state in self
        # returns: the correct response to the query obtained by asking DNS name servers
        # Your code goes here, when you change any 'self' variables make sure to use a lock

        # The socket that will be used to send/recieve info
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        q = DNSQuery(query)

        # Getting query information
        q_name = q.question['NAME']
        q_type = q.question['QTYPE']
        q_class = q.question['QCLASS']

        a = DNSQuery()
        a.header['ID'] = q.header['ID']
        a.header['QR'] = 1
        a.header['RD'] = 1
        a.header['RA'] = 1
        a.header['QDCOUNT'] = 1
        a.question = q.question

        # Handle Non-Recursive Queries
        if q.header['RD'] == 0:
            a.header['RCODE'] = RCODE_SERVFAIL
            return a.to_bytes()

        # Handle Inverse Queries
        if q_type == QTYPE_PTR:
            a.header['RCODE'] = RCODE_NOTIMP
            return a.to_bytes()

        # Handle eDNS (OPT RRs in query answer)
        if q.header['ARCOUNT'] != 0 and len(q.answers) != 0:
            for ans in q.answers:
                if ans['TYPE'] == TYPE_OPT:
                    a.header['RCODE'] = RCODE_FORMERR

        # Run the recursive algorithm
        # ans_list is a list of answers (full RRs)
        ans_list, r_code = self.rec_resolve(sock, [], self.format_query(q_name, q_type, q_class))

        if r_code != 0:
            a.header['RCODE'] = r_code

        # Count response types
        if r_code == RCODE_NXDOMAIN:
            a.header['NSCOUNT'] = len(ans_list)
        elif q_type == QTYPE_STAR:
            a.header['ANCOUNT'] = len(ans_list)
        else:
            for rr in ans_list:
                if rr['TYPE'] == TYPE_CNAME or rr['TYPE'] == q_type:
                    a.header['ANCOUNT'] += 1
                else:
                    a.header['NSCOUNT'] += 1

        a.answers = ans_list

        return a.to_bytes()


parser = argparse.ArgumentParser(description="""This is a DNS resolver""")
parser.add_argument('port', type=int, help='This is the port to connect to the resolver on', action='store')
args = parser.parse_args(argv[1:])
resolver = MyResolver(args.port)
resolver.wait_for_requests()
