#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>    /* errno variable */
#include <sys/types.h>
#include <sys/socket.h>       /* struct sockaddr */
#include <net/if_packet.h>    /* (may be </sys/if_packet.h>) */
#include <net/if.h>           /* struct ifreq */
#include <linux/sockios.h>    /* SIOCGIFINDEX (may be </bits/ioctls.h>) */
#include <linux/if_ether.h>    /* SIOCGIFINDEX (may be </bits/ioctls.h>) */
#include <unistd.h>
#include <fcntl.h>
#include <netpacket/packet.h> /* struct sockaddr_ll(may be </linux/packet.h>)*/
#include <linux/socket.h>     /* SOL_PACKET */

#define MAX_PACKET 10000

char buf[MAX_PACKET][2000];
int size[MAX_PACKET];

int main(int argc, char *argv[])
{

  int fd;
  int count = 0;
  struct sockaddr_ll addr;
  struct sockaddr from;
  struct packet_mreq pmreq;
  int i, ii;
  int res;
  int num;
  struct ifreq IFinfo;

  if (argc < 2) {
    printf("Usage: a.out num_packet\n");
    exit(0);
  }

  num = atoi(argv[1]);

  if ((num <= 0)  || (num >= MAX_PACKET)) {
    printf("num of packets = %d, out of the range of 0..%d\n",
	   num, MAX_PACKET);
    exit(0);
  }

  if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Can't open socket\n");
    exit(0);
  }

  memset(&IFinfo, 0, sizeof(IFinfo));
  strcpy(IFinfo.ifr_name, "eth0");

  if (ioctl(fd, SIOCGIFINDEX, &IFinfo) < 0) {
    printf("Can't find interface information.\n");
    exit(0);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = IFinfo.ifr_ifindex;
  /*  strncpy(addr.spkt_device, "eth0", sizeof(addr.spkt_device)); */
  /*
  addr.sll_pkttype = PACKET_HOST;
  addr.sll_halen = 6;
  */

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    printf("bind failed.\n");
    exit(0);
  }

  pmreq.mr_ifindex = IFinfo.ifr_ifindex;
  pmreq.mr_type = PACKET_MR_PROMISC;
  pmreq.mr_alen = 0;

  if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&pmreq, sizeof(pmreq)) < 0) {
    printf("setsockopt failed\n");
    exit(0);
  }

  /* now try to read a packet */
  while (count < num) {
    int length;

    length = sizeof(from);
    size[count] = recvfrom(fd, buf[count], 2000, 0, &from, &length);
    /*    printf("get packet %d: size %d\n", count, size[count]);  */
    count++;
  }

  ii = open("dumpfile", O_RDWR | O_CREAT | O_TRUNC, 0777);
  if (ii < 0) {
    printf("Cannot create dumpfile\n");
    exit(0);
  }

  for (i=0; i<count; i++) {
    int aa;

    aa = htonl(size[i]);
    res = write(ii, &(aa), sizeof(aa));
    if (res != sizeof(aa)) {
      printf("dumpfile corrupted1\n");
      exit(0);
    }

    res = write(ii, buf[i], size[i]);
    if (res != size[i]) {
      printf("dumpfile corrupted\n");
      exit(0);
    }
  }
  res = 0;
  for (i=0; i<count; i++) {
    res += 4 + size[i];
  }
  printf("final file size = %d\n", res);
}
