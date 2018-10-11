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

#define BUFFER_SIZE 4000

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

struct header {
	// Flags
	int synf, ackf, rstf, nulf, busyf;
	uint8_t seq;
	uint8_t ack;
	uint8_t vsn;
	int chk;
	uint8_t max_outstanding_segs;
	uint16_t max_seg_size;
	uint16_t retrans_timeout;
	uint16_t cum_ack_timeout;
	uint16_t null_timeout;
	uint8_t max_num_retrans;
	uint8_t max_cum_ack;
	uint8_t timeout_unit;
	uint32_t conn_id;
}; 

void header_to_bytes(struct header *hdr, uint16_t *bytes){

	bytes[0] = (hdr->synf << 15) | (hdr->ackf << 14) | (hdr->rstf << 12) | (hdr->nulf << 11) | (hdr->busyf << 8);
	bytes[1] = (hdr->seq << 8) | (hdr->ack);

	if (!hdr->synf){
		bytes[0] = bytes[0] | 8;
		bytes[2] = 0;
		bytes[3] = compsum(bytes, 4);
	} else{
		bytes[0] = bytes[0] | 24;
		bytes[2] = (hdr->vsn << 12) | (1 << 11) | (hdr->chk << 10) | hdr->max_outstanding_segs;
		bytes[3] = hdr->max_seg_size;

		bytes[4] = hdr->retrans_timeout; 
		bytes[5] = hdr->cum_ack_timeout;
		bytes[6] = hdr->null_timeout;
		bytes[7] = (hdr->max_num_retrans << 8) | hdr->max_cum_ack;

		bytes[8] = hdr->timeout_unit;
		bytes[9] = hdr->conn_id >> 16;
		bytes[10] = hdr->conn_id % (1 << 16);
		bytes[11] = compsum(bytes, 12);
	}
}

int bytes_to_header(uint16_t *bytes, struct header *hdr){
	if (bytes[11] != compsum(bytes, (bytes[0] % (1<<8)) / 2)){
		printf("Checksum is not valid!");
		return 0;
	}

	hdr->synf = (bytes[0] >> 15) % 2;
	hdr->ackf = (bytes[0] >> 14) % 2;
	hdr->rstf = (bytes[0] >> 12) % 2;
	hdr->nulf = (bytes[0] >> 11) % 2;
	hdr->busyf = (bytes[0] >> 8) % 2;
	hdr->seq = bytes[1] >> 8;
	hdr->ack = bytes[1] % (1<<8);

	if (hdr->synf){
		hdr->vsn = bytes[2] >> 12;
		hdr->chk = (bytes[2] >> 10) % 2;
		hdr->max_outstanding_segs = bytes[2] % (1<<8);
		hdr->max_seg_size = bytes[3];
		hdr->retrans_timeout = bytes[4];
		hdr->cum_ack_timeout = bytes[5];
		hdr->null_timeout = bytes[6];
		hdr->max_num_retrans = bytes[7] << 8;
		hdr->max_cum_ack = bytes[7] % (1<<8);
		hdr->timeout_unit = bytes[8] ;
		hdr->conn_id = bytes[9] << 16 | bytes[10];
	}

	return 1;
}

void print_header(struct header *hdr){
	printf("[ ");
	if (hdr->synf)
		printf("SYN ");
	if (hdr->ackf)
		printf("ACK ");
	if (hdr->rstf)
		printf("RST ");
	if (hdr->nulf)
		printf("NUL ");
	if (hdr->busyf)
		printf("BUSY ");

	printf("| %d | %d ]\n", hdr->seq, hdr->ack);

	if (hdr->synf){
		printf("VSN: %d \t CHK: %d\n", hdr->vsn, hdr->chk);
		printf("Max outstanding segs: %d\n", hdr->max_outstanding_segs);
		printf("Max seg size: %d\n", hdr->max_seg_size);
		printf("Retransmission timeout: %d\n", hdr->retrans_timeout);
		printf("Cumulative ACK timeout: %d\n", hdr->cum_ack_timeout);
		printf("Null timeout: %d\n", hdr->null_timeout);
		printf("Max Number of Retransmissions: %d\n", hdr->max_num_retrans);
		printf("Max number of cumulative ACKs: %d\n", hdr->max_cum_ack);
		printf("Timeout unit: %d\n", hdr->timeout_unit);
		printf("Connection ID: %d\n", hdr->conn_id);
	}
}

void write_header(int fd, struct header *hdr, uint16_t *byte_array){
	header_to_bytes(hdr, byte_array);
	int size = hdr->synf ? 24 : 8;
	for (int i = 0; i < size / 2; i++)
		byte_array[i] = htons(byte_array[i]);
	write(fd, byte_array, size);
}

void read_header(int fd, struct header *hdr, uint16_t *buffer){
	int bytes_transferred = read(fd, buffer, BUFFER_SIZE);
	for (int i = 0; i < bytes_transferred/2;  i++)
		buffer[i] = ntohs(buffer[i]);
	bytes_to_header(buffer, hdr);
}

int
main(int argc, const char **argv)
{
	struct sockaddr_in addr;
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

	// /*
	//  * Connection flow (from https://confluence.slac.stanford.edu/pages/viewpage.action?pageId=211782868):
	//  * 1. Send SYN to remote end
	//  * 2. Receive SYN segment back with a valid ACK number
	//  * 3. Reply to server with valid ACK segment.
	uint8_t seq = 19;
	uint8_t ack = 0;
	uint16_t buffer[BUFFER_SIZE];

	struct header hdr;
	hdr.synf = 1;
	hdr.ackf = 0;
	hdr.seq = seq;
	hdr.ack = 0;
	hdr.vsn = 1;
	hdr.chk = 1;
	hdr.max_outstanding_segs = 8;
	hdr.max_seg_size = 1024;
	hdr.retrans_timeout = 10;
	hdr.cum_ack_timeout = 100;
	hdr.null_timeout = 100;
	hdr.max_num_retrans = 16;
	hdr.max_cum_ack = 16;
	hdr.timeout_unit = 3;
	hdr.conn_id = 0;

	printf("HEADER SENT:\n");
	print_header(&hdr);

	write_header(fd, &hdr, buffer);
	read_header(fd, &hdr, buffer);

	printf("HEADER RECEIVED:\n");
	print_header(&hdr);
	// print_syn(&syn);
	return 0;

	// uint16_t hdr[12];
	// hdr[0] = RSSI_SYN | (24);
	// hdr[1] = (seq++) << 8;
	// hdr[2] = (1 << 12) | (8) | (1 << 11) | (1 << 10); 
	// hdr[3] = 1024; /* Max packet size in bytes */

	// hdr[4] = 10; /* retransmission timeout (ms) */
	// hdr[5] = 100; /* cumulative ack timeout (ms) */
	// hdr[6] = 100; /* dead connection timeout (ms) */
	// hdr[7] = (16 << 8) | (16 << 0); /* Number of retransmissions before giving up */

	// hdr[8] = 3;  previous numbers in ms (10^-3) 
	// hdr[9] = 0;
	// hdr[10] = 0;
	// hdr[11] = compsum(hdr, 12) ;

	// send_header(fd, hdr, 1);

	// /* Step 2 */
	// uint16_t resp[12];
	// read_header(fd, resp, 1);


	// /* Creates ACK packet */
	// hdr[0] = RSSI_NUL |  RSSI_ACK | (8);
	// hdr[1] = ((seq++) << 8) | (resp[1] >> 8);
	// hdr[2] = 0;
	// hdr[3] = compsum(hdr, 4);
	// send_header(fd ,hdr, 1);

	// /* Data Transfer Phase */
	// int counter = 0;
	// while (1){
	// 	if (counter % 5 == 0){
	// 		hdr[0] = RSSI_NUL |  RSSI_ACK | (8);
	// 		hdr[1] = ((seq++) << 8) | (resp[1] >> 8);
	// 		hdr[2] = 0;
	// 		hdr[3] = compsum(hdr, 4);
	// 		send_header(fd ,hdr, 1);
	// 		send_header(fd ,hdr, 1);
	// 		send_header(fd ,hdr, 1);

	// 	}
	// 	read_header(fd, resp, 1);
	// 	counter++;
	// }

	return (0);
}
