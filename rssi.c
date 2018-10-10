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

#define VERSION_NUMBER 1
#define CHK 1

struct Header {
	uint8_t flags;
	uint8_t seq;
	uint8_t ack;
};

struct syn_header{
	uint8_t max_outstanding_segs;
	uint16_t max_seg_size;
	uint16_t retrans_timeout;
	uint16_t cum_ack_timeout;
	uint16_t null_timeout;
	uint8_t timeout_unit;
	uint16_t conn_id_MSB;
	uint16_t conn_id_LSB;
};

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

void print_byte(uint8_t byte){
	for (int i = 0; i < 8; i++){
		printf("%d", (byte >> (7-i))%2);
	}
}

void print_header(uint16_t* syn, uint8_t size){
	for (int i = 0; i < size; i++){
		printf("%d:\t", i);
		print_byte(syn[i] >> 8);
		printf(" | ");
		print_byte(syn[i]);
		printf("\t(%d) \n", syn[i]);
	}
}

void send_header(int fd, uint16_t* header, int verbose){
	uint8_t header_size = (header[0] % (1<<8)) / 2;
	uint16_t hdr_cpy[header_size];

	if (verbose){
		printf("----------------------\n");
		printf("Sending %d bytes: \n", header_size * 2);
		print_header(header, header_size);
		printf("----------------------\n");
	}

	for (int i = 0; i < header_size; i++){
		hdr_cpy[i] = htons(header[i]);
	}

	write(fd, hdr_cpy, sizeof(hdr_cpy));
}

void read_header(int fd, uint16_t* resp, int verbose){
	int bytes_transferred = read(fd, resp, 100);
	uint8_t header_size = (resp[0] >> 8) / 2;

	for (int i = 0; i < header_size; i++){
		resp[i] = ntohs(resp[i]);
	}

	if (verbose){
		printf("----------------------\n");
		printf("Recieving %d bytes: ", header_size * 2);
		if (bytes_transferred > 2 * header_size){
			printf("(%d bytes of data attached)", bytes_transferred - 2 * header_size);
		}
		printf("\n");
		print_header(resp, header_size);
		printf("----------------------\n");
	}
}


int
main(int argc, const char **argv)
{
	struct sockaddr_in addr;
	uint8_t seq = 8;
	int fd, err, i;
	uint16_t buf[9000];

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

	uint16_t hdr[12];
	hdr[0] = RSSI_SYN | (24);
	hdr[1] = (seq++) << 8;
	hdr[2] = (1 << 12) | (8) | (1 << 11) | (1 << 10); 
	hdr[3] = 1024; /* Max packet size in bytes */

	hdr[4] = 10; /* retransmission timeout (ms) */
	hdr[5] = 100; /* cumulative ack timeout (ms) */
	hdr[6] = 100; /* dead connection timeout (ms) */
	hdr[7] = (16 << 8) | (16 << 0); /* Number of retransmissions before giving up */

	hdr[8] = 3; /* previous numbers in ms (10^-3) */
	hdr[9] = 0;
	hdr[10] = 0;
	hdr[11] = compsum(hdr, 12) ;

	send_header(fd, hdr, 1);

	/* Step 2 */
	uint16_t resp[12];
	read_header(fd, resp, 1);


	/* Creates ACK packet */
	hdr[0] = RSSI_NUL |  RSSI_ACK | (8);
	hdr[1] = ((seq++) << 8) | (resp[1] >> 8);
	hdr[2] = 0;
	hdr[3] = compsum(hdr, 4);

	send_header(fd ,hdr, 1);
	read_header(fd, resp, 1);
	read_header(fd, resp, 1);
	read_header(fd, resp, 1);
	
	hdr[0] = RSSI_NUL | RSSI_ACK | (8);
	hdr[1] = (seq++ << 8) | (resp[1] >> 8);
	hdr[3] = compsum(hdr, 4);

	send_header(fd ,hdr, 1);
	read_header(fd, resp, 1);
	read_header(fd, resp, 1);
	read_header(fd, resp, 1);

	return (0);
}
