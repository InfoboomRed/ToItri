#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <stdint.h>
#include <unistd.h>
#include "apdu_cyper.h"

#define SPI_DEV_NAME "/dev/spidev0.1"
#define SPI_MODE 0
#define SPI_BITS_PER_WORD 8
#define SPI_MAX_SPEED_HZ 1000000

#ifndef SPI_LSB_FIRST
#define SPI_LSB_FIRST 0
#endif

static int spi_fd = -1;
static char device[] = SPI_DEV_NAME;
static uint8_t temp_buf[2048] = {0};			// Not sure how to handle nearly 5K bytes of data with SPI (like DILITHIUM5),
static uint8_t temp_receive_buf[2048] = {0};  	// but here I fix the buf_length and receive all data at once.
static uint8_t mode = SPI_MODE;					// Temporarily.
static uint8_t bits = SPI_BITS_PER_WORD;
static uint32_t speed = SPI_MAX_SPEED_HZ;
static uint8_t lsb = SPI_LSB_FIRST;

uint8_t pk[KYBER_512_PUBLICKEYBYTES];
uint8_t sk[KYBER_512_SECRETKEYBYTES];

typedef struct
{
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint16_t lc;
	uint16_t le; 	// length of the response data
	uint8_t *data;	// command data
	uint8_t *rsp; 	// response data
	uint8_t state;
	uint8_t rsp_code;
	uint16_t index; 

}apdu_t;
apdu_t my_apdu;

int ss_mspi_open();
int ss_mspi_close();
int spi_transfer_ask(uint8_t const *tx, uint8_t const *rx, size_t len,int log_flag_tx,int log_flag_rx);
void apdu_status_check();
void apdu_kyber512_keypair();
void apdu_kyber512_kem_encap();
void apdu_set_buffer(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t lc);
void hex_dump(const void *src, size_t length, size_t line_size,char *prefix);



int main(int argc, char *argv[])
{
    int i, ret;
    int flag = 0;

    printf("APDU test start! \n");

    flag = atoi(argv[1]);

    if(flag == 0){
        ret = ss_mspi_open();
        if (ret < 0){
            return -1;
        }

        for(i = 0; i < 1; i++){
            printf("Send test pettern 91aabbcc0000\n");
            apdu_status_check();
            printf("apdu test pettern 90/91 Done.\n");
        }

        printf("-----------------------------------\n");
    }
    else if(flag == 1){
        ret = ss_mspi_open();
        if (ret < 0){
            return -1;
        }

        for(i = 0; i < 1; i++){
        
            printf("Send test pettern apdu_kyber512_keypair() \n");
            apdu_kyber512_keypair();
            printf("apdu test pettern kyber512_keypair Done. \n");
        }

        printf("-----------------------------------\n");
    }else if(flag == 4){
        // Add your additional code here
        
    }

    return 0;
}

int ss_mspi_open()
{
    int ret = 0;

    if (spi_fd >= 0)
        return -1;

    spi_fd = open(device, O_RDWR);
    if (spi_fd < 0)
    {
        printf("can't open %s\n", device);
        return -1;
    }

    // set mspi mode
    ret = ioctl(spi_fd, SPI_IOC_WR_MODE, &mode);
    if (ret < 0)
    {
        printf("can't set spi mode\n");
        close(spi_fd);
        return -1;
    }

    ret = ioctl(spi_fd, SPI_IOC_RD_MODE, &mode);
    if (ret < 0)
    {
        printf("can't get spi mode\n");
        close(spi_fd);
        return -1;
    }

    // set bits per word
    ret = ioctl(spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    if (ret < 0)
    {
        printf("can't set bits per word\n");
        close(spi_fd);
        return -1;
    }

    ret = ioctl(spi_fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
    if (ret < 0)
    {
        printf("can't get bits per word\n");
        close(spi_fd);
        return -1;
    }

    // set mspi speed hz
    ret = ioctl(spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
    if (ret < 0)
    {
        printf("can't set max speed hz\n");
        close(spi_fd);
        return -1;
    }

    ret = ioctl(spi_fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
    if (ret < 0)
    {
        printf("can't get max speed hz\n");
        close(spi_fd);
        return -1;
    }

    ret = ioctl(spi_fd, SPI_IOC_RD_LSB_FIRST, &lsb);
    if (ret < 0)
    {
        printf("mspi get lsb first failed!\n");
        close(spi_fd);
        return -1;
    }

    printf("mspi mode: %d\n", mode);
    printf("mspi bits per word: %d\n", bits);
    printf("mspi speed: %d Hz\n", speed);
    printf("mspi transmit is lsb first: %d\n", lsb);

    return 0;
}

int ss_mspi_close()
{
    if (spi_fd < 0)
        return -1;

    close(spi_fd);
    spi_fd = -1;

    printf("\nclose %s success\n", device);

    return 0;
}

void apdu_status_check()
{
    int ret = 0;

    my_apdu.cla = APDU_CLA_DEV_INIT;
    my_apdu.ins = 0xaa;
    my_apdu.p1 = 0xbb;
    my_apdu.p2 = 0xcc;
    my_apdu.lc = 0;
    my_apdu.index = 0;
    my_apdu.le = 0;
    apdu_set_buffer(my_apdu.cla, my_apdu.ins, my_apdu.p1, my_apdu.p2, my_apdu.lc);
    ret = spi_transfer_ask(temp_buf, temp_receive_buf, 6, 1, 1);

    if (ret < 0){
        printf("transfer error\n");
        ss_mspi_close();
    }

    printf("apdu send 91 OK %04x\r\n", my_apdu.lc);
}


void apdu_kyber512_keypair() {
    int ret = 0;
    uint8_t *pTemp;

	uint8_t pk[KYBER_512_PUBLICKEYBYTES];
	memset(pk, 0, KYBER_512_PUBLICKEYBYTES);
	uint8_t sk[KYBER_512_SECRETKEYBYTES];
    memset(sk, 0, KYBER_512_SECRETKEYBYTES);

    my_apdu.cla = APDU_CLA_ITRI;
    my_apdu.ins = ALGO_KYBER_512;
    my_apdu.p1 = CMD_KEM_KEYPAIR;
    my_apdu.p2 = 0x00;  			// Reserved fields, which can be set as needed
    my_apdu.lc = 0;
    my_apdu.index = 0;
    my_apdu.le = KYBER_512_PUBLICKEYBYTES + KYBER_512_SECRETKEYBYTES;

    apdu_set_buffer(my_apdu.cla, my_apdu.ins, my_apdu.p1, my_apdu.p2, my_apdu.lc);
    pTemp = &temp_buf[7];
    memcpy(pTemp, pk, KYBER_512_PUBLICKEYBYTES);
    pTemp += KYBER_512_PUBLICKEYBYTES;
    memcpy(pTemp, sk, KYBER_512_SECRETKEYBYTES);
    pTemp += KYBER_512_SECRETKEYBYTES;
    *pTemp = 0;
    *(pTemp+1) = my_apdu.le &0xff;
    *(pTemp+2) = (my_apdu.le >> 8) & 0xFF;
    ret = spi_transfer_ask(temp_buf, temp_receive_buf, sizeof(temp_buf), 1, 1);
    if (ret < 0) {
        printf("transfer error\n");
        ss_mspi_close();
        return;
    }
    printf("APDU KeyPair Kyber512 command sent OK, lc: %04x\n", my_apdu.lc);
}

void apdu_kyber512_kem_encap(const uint8_t *pk, uint8_t *ct, uint8_t *ss) {
    int ret = 0;
    uint8_t *pTemp;

    my_apdu.cla = APDU_CLA_ITRI;
    my_apdu.ins = ALGO_KYBER_512;
    my_apdu.p1 = CMD_KEM_ENCAP;
    my_apdu.p2 = 0x00;  					// Reserved fields, which can be set as needed
    my_apdu.lc = KYBER_512_PUBLICKEYBYTES;  // pk length
    my_apdu.index = pk;
    my_apdu.le = KYBER_512_CIPHERTEXTBYTES + SSBYTES;  // ACK_len == length of ct + ss

    apdu_set_buffer(my_apdu.cla, my_apdu.ins, my_apdu.p1, my_apdu.p2, my_apdu.lc);
    pTemp = &temp_buf[7];
    memcpy(pTemp, pk, KYBER_512_PUBLICKEYBYTES);
    pTemp += KYBER_512_PUBLICKEYBYTES;
    *pTemp = 0;
    *(pTemp+1) = my_apdu.le &0xff;
    *(pTemp+2) = (my_apdu.le >> 8) & 0xFF;

    ret = spi_transfer_ask(temp_buf, temp_receive_buf, sizeof(temp_buf), 1, 1);
    if (ret < 0) {
        printf("transfer error\n");
        ss_mspi_close();
        return;
    }

    printf("APDU Kyber512 KEM Encapsulation command sent OK, lc: %04x\n", my_apdu.lc);
}


void apdu_dilithium2_sign(const uint8_t *message, size_t message_len, uint8_t *signature, size_t *signature_len, const uint8_t *sk) {
    int ret = 0;
    uint8_t *pTemp;

    my_apdu.cla = APDU_CLA_ITRI;
    my_apdu.ins = ALGO_DILITHIUM2;
    my_apdu.p1 = CMD_DSA_SIGN1;
    my_apdu.p2 = 0x00;  					// Reserved fields, which can be set as needed
    my_apdu.lc = message_len;  				// message length, depands on case.
    my_apdu.index = message;				// message
    my_apdu.le = DILITHIUM2_SIGNATUREBYTES;

    apdu_set_buffer(my_apdu.cla, my_apdu.ins, my_apdu.p1, my_apdu.p2, my_apdu.lc);
    pTemp = &temp_buf[7];
    memcpy(pTemp, message, message_len);
    pTemp += message_len;
    *pTemp = 0;
    *(pTemp+1) = my_apdu.le &0xff;
    *(pTemp+2) = (my_apdu.le >> 8) & 0xFF;

    ret = spi_transfer_ask(temp_buf, temp_receive_buf, sizeof(temp_buf), 1, 1);
    if (ret < 0) {
        printf("transfer error\n");
        ss_mspi_close();
        return;
    }

    printf("APDU Dilithium2 Sign command sent OK, lc: %04x\n", my_apdu.lc);
}


void apdu_set_buffer(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t lc)
{
    temp_buf[0] = cla;
    temp_buf[1] = ins;
    temp_buf[2] = p1;
    temp_buf[3] = p2;
    if(lc > 0){
        temp_buf[4] = 0;    //fixed 0
        temp_buf[5] = lc & 0xFF;
        temp_buf[6] = (lc >> 8) & 0xFF;
    }
    //temp_buf[7] = 0;
    //temp_buf[8] = le & 0xFF;
    //temp_buf[9] = (le >> 8) & 0xFF;
}

void hex_dump(const void *src, size_t length, size_t line_size, char *prefix)
{
    int i = 0;
    const unsigned char *address = src;
    const unsigned char *line = address;
    unsigned char c;

    printf("%s | ", prefix);
    while (length-- > 0) {
        printf("%02X ", *address++);
        if (!(++i % line_size) || (length == 0 && i % line_size)) {
            if (length == 0) {
                while (i++ % line_size)
                    printf("__ ");
            }
            printf(" |");
            while (line < address) {
                c = *line++;
                printf("%c", (c < 32 || c > 126) ? '.' : c);
            }
            printf("|\n");
            if (length > 0)
                printf("%s | ", prefix);
        }
    }
}

int spi_transfer_ask(uint8_t const *tx, uint8_t const *rx, size_t len, int log_flag_tx, int log_flag_rx)
{
    int ret;
    int fd = spi_fd;
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = len,
        .delay_usecs = 0,
        .speed_hz = speed,
        .bits_per_word = bits,
    };

    if (mode & SPI_TX_QUAD)
        tr.tx_nbits = 4;
    else if (mode & SPI_TX_DUAL)
        tr.tx_nbits = 2;
    if (mode & SPI_RX_QUAD)
        tr.rx_nbits = 4;
    else if (mode & SPI_RX_DUAL)
        tr.rx_nbits = 2;
    if (!(mode & SPI_LOOP)) {
        if (mode & (SPI_TX_QUAD | SPI_TX_DUAL))
            tr.rx_buf = 0;
        else if (mode & (SPI_RX_QUAD | SPI_RX_DUAL))
            tr.tx_buf = 0;
    }

    ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 1){
        printf("ERROR!\n");
        return -1;
    }

    if (log_flag_tx){
        hex_dump(tx, len, 32, "TX");
    }

    if (log_flag_rx){
        hex_dump(rx, len, 32, "RX");
    }

    return 0;
}
