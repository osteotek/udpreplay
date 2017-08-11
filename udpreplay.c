#include "net/ethernet.h"
#include "string.h"
#include "net/if.h"
#include "arpa/inet.h"
#include "netdb.h"
#include "errno.h"
#include "netinet/ip.h"
#include "netinet/udp.h"
#include "pcap/pcap.h"
#include "unistd.h"
#include "stdlib.h"

int main(int argc, char *argv[])
{
  static const char usage[] =
      " [-i iface] [-l] [-s speed] pcap\n"
      "\n"
      "  -i iface    interface to send packets through\n"
      "  -l          or enable loopback\n"
      "              -i and -l options are mutually exclusive\n"
      "  -s speed    replay speed relative to pcap timestamps\n"
      "              (higher -> slower)\n";

  int ifindex = 0;
  int loopback = 0;
  double speed = 1.0;
  struct in_addr localhost = {};

  int opt;
  while ((opt = getopt(argc, argv, "i:ls:")) != -1)
  {
    switch (opt)
    {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0)
      {
        fprintf(stderr, "if_nametoindex: %s\n", strerror(errno));
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = strtod(optarg, NULL);
      break;
    default:
      fprintf(stderr, "Error: %s\n", usage);
      return 1;
    }
  }

  if (optind >= argc)
  {
    fprintf(stderr, "usage: %s\n", usage);
    return 1;
  }

  if (ifindex && loopback)
  {
    fprintf(stderr, "error: -i and -l options can't be used at the same time\n");
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1)
  {
    fprintf(stderr, "socket: %s\n", strerror(errno));
    return 1;
  }

  if (ifindex)
  {
    struct ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) == -1)
    {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
    }
  }

  if (loopback)
  {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) == -1)
    {
      fprintf(stderr, "setsockopt: %s\n", strerror(errno));
      return 1;
    }
    char localhostname[128];
    gethostname(localhostname, sizeof localhostname);
    struct hostent *he;

    if ((he = gethostbyname(localhostname)) == NULL)
    {
      herror("gethostbyname");
      return 1;
    }
    localhost = *(struct in_addr *)he->h_addr;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(argv[optind], errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "pcap_open: %s\n", strerror(errno));
    return 1;
  }

  struct pcap_pkthdr header;
  const u_char *p;
  struct timeval tv = {0, 0};
  while ((p = pcap_next(handle, &header)))
  {
    if (header.len != header.caplen)
    {
      continue;
    }
    struct ether_header *eth = (struct ether_header *)(p);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    {
      continue;
    }
    struct ip *ip_header = (struct ip *)(p + sizeof(struct ether_header));
    if (ip_header->ip_v != 4)
    {
      continue;
    }
    if (ip_header->ip_p != IPPROTO_UDP)
    {
      continue;
    }
    struct udphdr *udp = (struct udphdr *)(p + sizeof(struct ether_header) + ip_header->ip_hl * 4);

    if (tv.tv_sec == 0)
    {
      tv = header.ts;
    }
    struct timeval diff;
    timersub(&header.ts, &tv, &diff);
    tv = header.ts;
    usleep((diff.tv_sec * 1000000 + diff.tv_usec) * speed);

    ssize_t len = ntohs(udp->uh_ulen) - 8;
    const u_char *payload = &p[sizeof(struct ether_header) + ip_header->ip_hl * 4 + sizeof(struct udphdr)];

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
#if __APPLE__
    addr.sin_port = udp->uh_dport;
#elif __linux__
    addr.sin_port = udp->dest;
#endif
    addr.sin_addr = loopback ? localhost : ip_header->ip_dst;

    int n = sendto(fd, payload, len, 0, (struct sockaddr *)(&addr), sizeof(addr));
    if (n != len)
    {
      fprintf(stderr, "sendto: %s\n", strerror(errno));
      return 1;
    }
  }

  return 0;
}
