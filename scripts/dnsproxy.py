import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR
from collections import defaultdict
import threading
import dns.resolver

class DNSLoadBalancer:
    def __init__(self, dns_servers):
        self.dns_servers = dns_servers
        self.server_usage = defaultdict(int)  # Track usage of each DNS server
        self.lock = threading.Lock()  # Thread-safe access to server_usage

    def get_least_used_server(self):
        """Return the DNS server with the least usage."""
        with self.lock:
            least_used_server = min(self.dns_servers, key=lambda x: self.server_usage[x])
            self.server_usage[least_used_server] += 1
            return least_used_server

    def resolve(self, domain, record_type="A"):
        """Resolve a domain using the least-used DNS server."""
        server = self.get_least_used_server()
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        try:
            answers = resolver.resolve(domain, record_type)
            return [rdata.to_text() for rdata in answers]
        except Exception as e:
            print(f"Failed with {server}: {e}")
            return None

class DNSProxy:
    def __init__(self, dns_servers, listen_port=53):
        self.dns_servers = dns_servers
        self.listen_port = listen_port
        self.load_balancer = DNSLoadBalancer(dns_servers)

    def start(self):
        """Start the DNS proxy server."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.bind(("0.0.0.0", self.listen_port))
            print(f"DNS Proxy listening on port {self.listen_port}...")
            while True:
                data, addr = udp_sock.recvfrom(1024)
                threading.Thread(target=self.handle_request, args=(data, addr)).start()

    def handle_request(self, data, addr):
        """Handle a DNS request and send back the response."""
        request = DNSRecord.parse(data)
        domain = str(request.q.qname)
        print(f"Received request for: {domain}")

        # Forward request to the least-used DNS server
        answers = self.load_balancer.resolve(domain)
        if answers:
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                q=request.q,
            )
            for answer in answers:
                reply.add_answer(RR(rname=request.q.qname, rtype=1, rdata=answer))
            response = reply.pack()
        else:
            # If resolution fails, return an empty response
            response = request.reply().pack()

        # Send the response back to the client
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.sendto(response, addr)

if __name__ == "__main__":
    # List of public DNS servers
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"]

    # Start the DNS proxy server
    proxy = DNSProxy(dns_servers)
    proxy.start()