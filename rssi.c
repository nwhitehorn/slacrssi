#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RSSI_SYN (1 << 15)
#define RSSI_ACK (1 << 14)
#define RSSI_RST (1 << 12)
#define RSSI_NUL (1 << 11)
#define RSSI_BUSY (1 << 8)

uint16_t
compsum(uint16_t *data, uint8_t size)
{
	uint8_t i;
	uint32_t sum;
	
	sum = 0;
	for (i = 0; i < size-1; i++)
		sum += data[i];

	sum = (sum % 0x10000) + (sum / 0x10000);
	sum ^= 0xffff;

	return (sum);
}

int
main(int argc, const char **argv)
{
	struct sockaddr_in addr;
	uint8_t seq = 0;
	int fd, err, i;
	uint8_t buf[9000];

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror(NULL);
		exit(1);
	}

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(8198);

	err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));

	/*
	 * Connection flow (from https://confluence.slac.stanford.edu/pages/viewpage.action?pageId=211782868):
	 * 1. Send SYN to remote end
	 * 2. Receive SYN segment back with a valid ACK number
	 * 3. Reply to server with valid ACK segment.
	 */

	uint16_t syn[12];
	syn[0] = RSSI_SYN | (24);
	syn[1] = (seq++) << 8;
	syn[2] = (2 << 12) | (255);
	syn[3] = 8500; /* Max packet size in bytes */

	syn[4] = 50; /* retransmission timeout (ms) */
	syn[5] = 100; /* cumulative ack timeout (ms) */
	syn[6] = 500; /* dead connection timeout (ms) */
	syn[7] = (16 << 8) | (16 << 0); /* Number of retransmissions before giving up */

	syn[8] = 3; /* previous numbers in ms (10^-3) */
	syn[9] = 0;
	syn[10] = 0;
	syn[11] = compsum(syn, 12);

	for (i = 0; i < 12; i++)
		syn[i] = htons(syn[i]);

	write(fd, syn, sizeof(syn));

	/* Step 2 */
	i = read(fd, syn, sizeof(syn));
	printf("Got back %d bytes\n", i);
	for (i = 0; i < 12; i++)
		syn[i] = ntohs(syn[i]);

	/* Step 3 */
	/* Accept remote sequence number */
	syn[1] = (syn[1] >> 8) | (seq++ << 8);
	syn[11] = compsum(syn, 12);
	for (i = 0; i < 12; i++)
		syn[i] = htons(syn[i]);

	write(fd, syn, sizeof(syn));
	
	while (1) {
		i = read(fd, buf, sizeof(buf));
		printf("Received %d bytes streamer packet\n", i);
	}

	return (0);
}
