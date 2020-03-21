/*
 * pcap_file_io.c
 *
 * functions for reading and writing packets using the (old) libpcap
 * file format
 * 
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at 
 * https://github.com/cisco/mercury/blob/master/LICENSE 
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE            /* get fadvise() and fallocate() */
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "mercury.h"
#include "pcap_file_io.h"
#include "pkt_proc.h"
#include "signal_handling.h"
#include "utils.h"
#include "llq.h"

/*
 * constants used in file format
 */
static uint32_t magic = 0xa1b2c3d4;
static uint32_t cagim = 0xd4c3b2a1;

/*
 * global pcap header (one per file, at beginning)
 */
struct pcap_file_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
};

/*
 * packet header (one per packet, right before it)
 */
struct pcap_packet_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};  // TBD: pack structure

#define ONE_KB (1024)
#define ONE_MB (1024 * ONE_KB)
#ifndef FBUFSIZE
   #define STREAM_BUFFER_SIZE (ONE_MB)
#else
   #define STREAM_BUFFER_SIZE FBUFSIZE
#endif
#define PRE_ALLOCATE_DISK_SPACE  (100 * ONE_MB)

static inline void set_file_io_buffer(struct pcap_file *f, const char *fname) {
    f->buffer = (unsigned char *) malloc(STREAM_BUFFER_SIZE);
    if (f->buffer != NULL) {
        if (setvbuf(f->file_ptr, (char *)f->buffer, _IOFBF, STREAM_BUFFER_SIZE) != 0) {
            printf("%s: error setting i/o buffer for file %s\n", strerror(errno), fname);
            free(f->buffer);
            f->buffer = NULL;
        } else {
            f->buf_len = STREAM_BUFFER_SIZE;
        }
    } else {
        printf("warning: could not malloc i/o buffer for %s\n", fname);
    }
}

enum status write_pcap_file_header(FILE *f) {
    struct pcap_file_hdr file_header;
    file_header.magic_number = magic;
    file_header.version_major = 2;
    file_header.version_minor = 4;
    file_header.thiszone = 0;     /* no GMT correction for now */
    file_header.sigfigs = 0;      /* we don't claim sigfigs for now */
    file_header.snaplen = 65535;
    file_header.network = 1;      /* ethernet */

    size_t items_written = fwrite(&file_header, sizeof(file_header), 1, f);
    if (items_written == 0) {
        perror("error writing pcap file header");
        return status_err;
    }
    return status_ok;
}

enum status pcap_file_open(struct pcap_file *f,
               const char *fname,
               enum io_direction dir,
               int flags) {
    struct pcap_file_hdr file_header;
    ssize_t items_read;

    switch(dir) {
    case io_direction_reader:
        f->flags = O_RDONLY;
        break;
    case io_direction_writer:
        f->flags = O_WRONLY;
        break;
    default:
        printf("error: unsupported flag, other flags=0x%x\n", flags);
        return status_err; /* unsupported flags */
    }

    if (f->flags == O_WRONLY) {
        /* create and open new file for writing */
        f->file_ptr = fopen(fname, "w");
        if (f->file_ptr == NULL) {
            printf("%s: error opening pcap file %s\n", strerror(errno), fname);
            return status_err; /* could not open file */
        }
        f->fd = fileno(f->file_ptr); // save file descriptor
        if (f->fd < 0) {
            printf("%s: error getting file descriptor for pcap file %s\n", strerror(errno), fname);
            return status_err; /* system call failed */
        }

        // set file i/o buffer
        set_file_io_buffer(f, fname);

        // set the file advisory for the read file
        if (posix_fadvise(f->fd, 0, 0, POSIX_FADV_SEQUENTIAL) != 0) {
            printf("%s: Could not set file advisory for pcap file %s\n", strerror(errno), fname);
        }

        f->allocated_size = 0; // initialize
        if (fallocate(f->fd, FALLOC_FL_KEEP_SIZE, 0, PRE_ALLOCATE_DISK_SPACE) != 0) {
            printf("warning: %s: Could not pre-allocate %d MB disk space for pcap file %s\n", 
                    strerror(errno), PRE_ALLOCATE_DISK_SPACE, fname);
        } else {
            f->allocated_size = PRE_ALLOCATE_DISK_SPACE;  // initial allocation
        }

        enum status status = write_pcap_file_header(f->file_ptr);
        if (status) {
            perror("error writing pcap file header");
            fclose(f->file_ptr);
            f->file_ptr = NULL;
            if (f->buffer != NULL) {
                free(f->buffer);
                f->buffer = NULL;
            }
            return status_err;
        }

        // initialize packets and bytes written
        f->bytes_written = sizeof(file_header);
        f->packets_written = 0;

    } else { /* O_RDONLY */

	/*  open existing file for reading */
	f->file_ptr = fopen(fname, "r");
	if (f->file_ptr == NULL) {
	    printf("%s: error opening read file %s\n", strerror(errno), fname);
	    return status_err; /* could not open file */
	}

	f->fd = fileno(f->file_ptr);  // save file descriptor
	if (f->fd < 0) {
	    printf("%s: error getting file descriptor for read file %s\n", strerror(errno), fname);
	    return status_err; /* system call failed */
	}

	// set the file advisory for the read file
	if (posix_fadvise(f->fd, 0, 0, POSIX_FADV_SEQUENTIAL) != 0) {
	    printf("%s: Could not set file advisory for read file %s\n", strerror(errno), fname);
	}

	// set file i/o buffer
	set_file_io_buffer(f, fname);
	f->bytes_written = 0L;  // will never write any bytes to this file opened for reading

	// printf("info: file %s opened\n", fname);

	items_read = fread(&file_header, sizeof(file_header), 1, f->file_ptr);
	if (items_read == 0) {
	    perror("could not read file header");
	    return status_err; /* could not read packet header from file */
	}
	if (file_header.magic_number == magic) {
	    f->byteswap = 0;
	    // printf("file is in pcap format\nno byteswap needed\n");
	} else if (file_header.magic_number == cagim) {
	    f->byteswap = 1;
	    // printf("file is in pcap format\nbyteswap is needed\n");
	} else {
	    printf("error: file %s not in pcap format (file header: %08x)\n",
		   fname, file_header.magic_number);
	    if (file_header.magic_number == 0x0a0d0d0a) {
		printf("error: pcap-ng format found; this format is currently unsupported\n");
	    }
	    exit(255);
	}
	if (f->byteswap) {
	    file_header.version_major = htons(file_header.version_major);
	    file_header.version_minor = htons(file_header.version_minor);
	    file_header.thiszone = htonl(file_header.thiszone);
	    file_header.sigfigs = htonl(file_header.sigfigs);
	    file_header.snaplen = htonl(file_header.snaplen);
	    file_header.network = htonl(file_header.network);
	}
    }

    return status_ok;
}


enum status pcap_file_write_packet_direct(struct pcap_file *f,
                      const void *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int usec) {
    size_t items_written;
    struct pcap_packet_hdr packet_hdr;

    if (packet && !length) {
	printf("warning: attempt to write an empty packet\n");
	return status_ok;
    }

    /* note: we never perform byteswap when writing */
    packet_hdr.ts_sec = sec;
    packet_hdr.ts_usec = usec;
    packet_hdr.incl_len = length;
    packet_hdr.orig_len = length;

    // write the packet header
    items_written = fwrite(&packet_hdr, sizeof(struct pcap_packet_hdr), 1, f->file_ptr);
    if (items_written == 0) {
        perror("error: could not write packet header to output file\n");
        return status_err;
    }

    // write the packet
    items_written = fwrite(packet, length, 1, f->file_ptr);
    if (items_written == 0) {
        perror("error: could not write packet data to output file\n");
        return status_err;
    }

    f->bytes_written += length + sizeof(struct pcap_packet_hdr);
    f->packets_written++;

    if ((f->allocated_size > 0) && (f->allocated_size - f->bytes_written) <= ONE_MB) {
        // need to allocate more
        if (fallocate(f->fd, FALLOC_FL_KEEP_SIZE, f->bytes_written, PRE_ALLOCATE_DISK_SPACE) != 0) {
            perror("warning: could not increase write file allocation by 100 MB");
        } else {
            f->allocated_size = f->bytes_written + PRE_ALLOCATE_DISK_SPACE;  // increase allocation
        }
    }

    return status_ok;
}


#define BUFLEN  16384

enum status pcap_file_read_packet(struct pcap_file *f,
                  struct pcap_pkthdr *pkthdr, /* output */
                  void *packet_data           /* output */
                  ) {
    ssize_t items_read;
    struct pcap_packet_hdr packet_hdr;

    if (f->file_ptr == NULL) {
        printf("File not open\n");
        return status_err;
    }

    items_read = fread(&packet_hdr, sizeof(packet_hdr), 1, f->file_ptr);
    if (items_read == 0) {
        return status_err_no_more_data; /* could not read packet header from file */
    }

    if (f->byteswap) {
        pkthdr->ts.tv_sec = ntohl(packet_hdr.ts_sec);
        pkthdr->ts.tv_usec = ntohl(packet_hdr.ts_usec);
        pkthdr->caplen = ntohl(packet_hdr.incl_len);
    } else {
        pkthdr->ts.tv_sec = packet_hdr.ts_sec;
        pkthdr->ts.tv_usec = packet_hdr.ts_usec;
        pkthdr->caplen = packet_hdr.incl_len;
    }

    if (pkthdr->caplen <= BUFLEN) {
        items_read = fread(packet_data, pkthdr->caplen, 1, f->file_ptr);
        if (items_read == 0) {
            printf("could not read packet from file, caplen: %u\n", pkthdr->caplen);
            return status_err;          /* could not read packet from file */
        }
    } else {
        /*
         * The packet length is much bigger than BUFLEN.
         * Read BUFLEN bytes to process the packet and skip the remaining bytes.
         */
        if (fread(packet_data, BUFLEN, 1, f->file_ptr) == 0) {
            printf("could not read %d bytes of the packet from file\n", (int)BUFLEN);
            return status_err;          /* could not read packet from file */
        }

        // advance the file pointer to skip the large packet
        if (fseek(f->file_ptr, pkthdr->caplen - BUFLEN, SEEK_CUR) != 0) {
            perror("error: could not advance file pointer\n");
            return status_err;
        }

        // adjust the packet len and caplen
        pkthdr->len = pkthdr->caplen;
        pkthdr->caplen = BUFLEN;
        return status_ok;
    }

    return status_ok;
}


void packet_info_init_from_pkthdr(struct packet_info *pi,
				  struct pcap_pkthdr *pkthdr) {
    pi->len = pkthdr->caplen;
    pi->caplen = pkthdr->caplen;
    pi->ts.tv_sec = pkthdr->ts.tv_sec;
    pi->ts.tv_nsec = pkthdr->ts.tv_usec * 1000;
} 

enum status pcap_file_dispatch_pkt_processor(struct pcap_file *f,
                                             struct pkt_proc *pkt_processor,
                                             int loop_count) {
    enum status status = status_ok;
    struct pcap_pkthdr pkthdr;
    uint8_t packet_data[BUFLEN];
    unsigned long total_length = sizeof(struct pcap_file_hdr); // file header is already written
    unsigned long num_packets = 0;
    struct packet_info pi;

    for (int i=0; i < loop_count && sig_close_flag == 0; i++) {
        do {
            status = pcap_file_read_packet(f, &pkthdr, packet_data);
            if (status == status_ok) {
                packet_info_init_from_pkthdr(&pi, &pkthdr);
                // process the packet that was read
                pkt_processor->apply(&pi, packet_data);
                num_packets++;
                total_length += pkthdr.caplen + sizeof(struct pcap_packet_hdr);
            }
        } while (status == status_ok && sig_close_flag == 0);
        
        if (i < loop_count - 1) {
            // Rewind the file to the first packet after skipping file header.
            if (fseek(f->file_ptr, sizeof(struct pcap_file_hdr), SEEK_SET) != 0) {
                perror("error: could not rewind file pointer\n");
                status = status_err;
            }
        }
    }

    pkt_processor->bytes_written = total_length;
    pkt_processor->packets_written = num_packets;

    if (status == status_err_no_more_data) {
        return status_ok;
    }
    return status;
}

enum status pcap_file_close(struct pcap_file *f) {
    if (fclose(f->file_ptr) != 0) {
	perror("could not close input pcap file");
	return status_err;
    }
    if (f->buffer) {
	free(f->buffer);
    }
    return status_ok;
}


uint8_t *get_test_packet(struct pcap_pkthdr *pkthdr) {

    static uint8_t pkt_large[] = {
 0x08, 0x00, 0x27, 0xbc, 0xd0, 0xe8, 0x08, 0x00, 0x27, 0xd0, 0x91, 0x4f, 0x08, 0x00, 0x45, 0x00,
 0x05, 0xce, 0xde, 0x5b, 0x40, 0x00, 0x40, 0x06, 0xd3, 0x78, 0xc0, 0xa8, 0x01, 0x03, 0xc0, 0xa8,
 0x01, 0x02, 0x01, 0xbb, 0xc1, 0x90, 0x74, 0x04, 0xd4, 0xff, 0xae, 0xc8, 0x4d, 0xe8, 0x80, 0x18,    
 0x00, 0xeb, 0xfb, 0xe0, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x01, 0x1e, 0x32, 0xff, 0xff,    
 0xa9, 0x69, 0x16, 0x03, 0x03, 0x00, 0x42, 0x02, 0x00, 0x00, 0x3e, 0x03, 0x03, 0x76, 0x1a, 0x66,    
 0xbf, 0x25, 0x9d, 0x9b, 0x26, 0x03, 0xa4, 0x50, 0x14, 0x5f, 0x33, 0xad, 0xcc, 0x13, 0x36, 0x7a,    
 0xe2, 0xdb, 0x41, 0xcd, 0x2d, 0xc3, 0xc0, 0x1b, 0x71, 0x51, 0x26, 0xf2, 0xf1, 0x00, 0xc0, 0x30,    
 0x00, 0x00, 0x16, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,    
 0x00, 0x23, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x03, 0xf3, 0x0b, 0x00,    
 0x03, 0xef, 0x00, 0x03, 0xec, 0x00, 0x03, 0xe9, 0x30, 0x82, 0x03, 0xe5, 0x30, 0x82, 0x02, 0xcd,    
 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xd4, 0x06, 0xf1, 0x2c, 0xcd, 0x07, 0x1e, 0x39,    
 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,    
 0x81, 0x88, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,    
 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31,    
 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e,    
 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72,    
 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20,    
 0x4c, 0x74, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x66, 0x75,    
 0x7a, 0x7a, 0x69, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a,    
 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x66, 0x75, 0x7a, 0x7a, 0x40, 0x65,    
 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38,    
 0x30, 0x31, 0x32, 0x33, 0x32, 0x33, 0x31, 0x32, 0x32, 0x34, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30,    
 0x31, 0x32, 0x33, 0x32, 0x33, 0x31, 0x32, 0x32, 0x34, 0x5a, 0x30, 0x81, 0x88, 0x31, 0x0b, 0x30,    
 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03,    
 0x55, 0x04, 0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,    
 0x55, 0x04, 0x07, 0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x31, 0x21, 0x30, 0x1f, 0x06,    
 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57,    
 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x14,    
 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x66, 0x75, 0x7a, 0x7a, 0x69, 0x6e, 0x67,    
 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,    
 0x01, 0x09, 0x01, 0x16, 0x10, 0x66, 0x75, 0x7a, 0x7a, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,    
 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,    
 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,    
 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc6, 0xbd, 0x08, 0x64, 0xf7, 0x30, 0x69, 0x92, 0x79, 0x13,    
 0xa0, 0x15, 0x73, 0x18, 0x78, 0xae, 0x1c, 0x53, 0x19, 0xcd, 0x97, 0x81, 0x19, 0x63, 0x70, 0x17,    
 0xfb, 0x1e, 0x89, 0xd0, 0xeb, 0xd0, 0xdb, 0xc3, 0x5b, 0x49, 0xe5, 0x4f, 0x57, 0xec, 0x7e, 0xb9,    
 0x2a, 0xf8, 0xd5, 0xb2, 0x9f, 0x9c, 0x6a, 0x3a, 0x1a, 0xa4, 0xde, 0x96, 0xd4, 0x4e, 0x6f, 0x72,    
 0x8b, 0xf0, 0xf6, 0x51, 0xaf, 0x79, 0x4c, 0xfa, 0x80, 0xbf, 0x65, 0x90, 0x47, 0x34, 0x7d, 0x64,    
 0x58, 0x54, 0xcc, 0x1e, 0xc6, 0x68, 0xee, 0xa8, 0x69, 0x90, 0xae, 0xf2, 0x32, 0xd3, 0x5c, 0x45,    
 0x6d, 0x81, 0x39, 0xd3, 0x6d, 0x2a, 0x65, 0xbc, 0x52, 0x0c, 0xc9, 0x63, 0x07, 0x7c, 0x76, 0xe7,    
 0x01, 0x28, 0x44, 0x7f, 0x8f, 0x21, 0x99, 0xeb, 0x64, 0xe5, 0x19, 0x40, 0x8b, 0xbc, 0x46, 0xbc,    
 0xde, 0xef, 0x0b, 0x4b, 0x5d, 0x74, 0xa2, 0x86, 0xff, 0x74, 0xc2, 0x6c, 0x46, 0xb4, 0xc0, 0xa5,    
 0xd1, 0xb7, 0xbd, 0x8d, 0x6b, 0xc1, 0xed, 0x11, 0xf3, 0x75, 0x9d, 0xa6, 0xeb, 0x76, 0xa5, 0xf8,    
 0x67, 0x1f, 0x11, 0x8b, 0xff, 0x06, 0x37, 0xc0, 0xe1, 0x04, 0xe3, 0x7c, 0x2d, 0xac, 0x78, 0xaa,    
 0x53, 0x4d, 0x68, 0xec, 0xda, 0xfc, 0x94, 0x66, 0x9e, 0x26, 0x96, 0x9a, 0x0d, 0xf0, 0x67, 0x36,    
 0xd4, 0xbe, 0x18, 0x94, 0x16, 0x35, 0x72, 0x00, 0xa2, 0x10, 0xbb, 0x4b, 0x45, 0x9d, 0xb7, 0x81,    
 0xd1, 0x0a, 0x2f, 0xaf, 0x87, 0x54, 0xf1, 0x8e, 0x2b, 0x88, 0xfa, 0x4b, 0xe8, 0x6e, 0x6a, 0x23,    
 0x4b, 0x9b, 0x88, 0xda, 0xef, 0xc6, 0xa7, 0xdd, 0xc2, 0x0d, 0xd6, 0x84, 0xa3, 0x9b, 0x26, 0xc8,    
 0xf9, 0xac, 0x9f, 0xda, 0xd8, 0x4d, 0x12, 0xfc, 0x78, 0x4e, 0x55, 0x06, 0xce, 0x2f, 0xab, 0x0f,    
 0x01, 0xda, 0x18, 0xd1, 0xbc, 0xf9, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x50, 0x30, 0x4e, 0x30,    
 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x09, 0x7e, 0xf9, 0xc0, 0x0e, 0x85,    
 0x22, 0x7e, 0x79, 0x80, 0x17, 0x4b, 0xa5, 0x98, 0xa5, 0x50, 0x4f, 0x23, 0xe5, 0x23, 0x30, 0x1f,    
 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x09, 0x7e, 0xf9, 0xc0, 0x0e,    
 0x85, 0x22, 0x7e, 0x79, 0x80, 0x17, 0x4b, 0xa5, 0x98, 0xa5, 0x50, 0x4f, 0x23, 0xe5, 0x23, 0x30,    
 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06,    
 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,    
 0x00, 0x2e, 0x6f, 0x96, 0xb2, 0x4a, 0x27, 0x2f, 0xb3, 0x26, 0xf2, 0x4a, 0x3a, 0x2d, 0x14, 0xca,    
 0xcf, 0x3a, 0x68, 0xa8, 0xab, 0xdd, 0x63, 0xf6, 0xa5, 0xa6, 0xaf, 0x0d, 0x93, 0x9b, 0x15, 0x76,    
 0x35, 0x90, 0x70, 0x8f, 0x23, 0x9e, 0x7b, 0x0e, 0xc7, 0xd4, 0x59, 0x7a, 0xca, 0x4b, 0xb8, 0x21,    
 0xb9, 0xbe, 0x0c, 0x28, 0x0c, 0x9e, 0x76, 0x25, 0xe7, 0x40, 0x8f, 0x39, 0x0d, 0xf5, 0x26, 0xf2,    
 0x54, 0x08, 0xc9, 0xf3, 0x9e, 0x32, 0x3b, 0xa3, 0x97, 0x23, 0x8a, 0x9b, 0x8e, 0x85, 0x6f, 0x85,    
 0x3c, 0x7c, 0x34, 0x45, 0xfa, 0x0c, 0x76, 0x25, 0xd0, 0x69, 0xc6, 0x68, 0xe9, 0xe2, 0x2d, 0x56,    
 0x42, 0x04, 0x65, 0xa6, 0xbf, 0x48, 0x19, 0x4c, 0xb2, 0xe9, 0x91, 0x51, 0x29, 0x5f, 0x95, 0x56,    
 0xc7, 0x9f, 0x67, 0x01, 0xa7, 0xb7, 0xde, 0x55, 0xb1, 0xdd, 0xa0, 0x86, 0x75, 0xe2, 0xaf, 0x9f,    
 0xf0, 0x51, 0x72, 0x09, 0xb9, 0x19, 0x4a, 0xe8, 0x7b, 0xe8, 0x07, 0x03, 0xed, 0x64, 0x2d, 0xe1,    
 0x0c, 0xb8, 0x9f, 0x5a, 0x58, 0x7a, 0x11, 0x92, 0x38, 0x8c, 0x57, 0x68, 0x69, 0x73, 0xae, 0x2d,    
 0xb6, 0x5e, 0x26, 0xe6, 0x82, 0xd2, 0x8b, 0x5f, 0x66, 0x91, 0x8c, 0xff, 0x47, 0x41, 0x62, 0x76,    
 0x5b, 0xec, 0x20, 0xd7, 0x80, 0x54, 0x20, 0xef, 0x93, 0x9a, 0xee, 0xf7, 0x3b, 0x01, 0x8f, 0x8f,    
 0x63, 0x3e, 0xf2, 0xc5, 0xfb, 0xba, 0x36, 0x11, 0x67, 0x0d, 0x6f, 0x16, 0x87, 0x74, 0x18, 0x25,    
 0x57, 0x02, 0x79, 0x93, 0x8c, 0x09, 0x40, 0x33, 0xdf, 0x98, 0xea, 0xf9, 0x24, 0x26, 0xb0, 0x2d,    
 0xbf, 0x20, 0xad, 0xbe, 0x82, 0xda, 0xa6, 0x28, 0x7a, 0xdf, 0x2f, 0x56, 0x20, 0x19, 0xd7, 0x43,    
 0x51, 0xf2, 0x92, 0xba, 0xa5, 0x5f, 0xd1, 0xc0, 0x9f, 0xd9, 0xc0, 0x10, 0x9e, 0x2b, 0xd0, 0x35,    
 0x05, 0x16, 0x03, 0x03, 0x01, 0x4d, 0x0c, 0x00, 0x01, 0x49, 0x03, 0x00, 0x17, 0x41, 0x04, 0xef,    
 0x35, 0x1e, 0xc1, 0xa2, 0x16, 0xe3, 0x06, 0x5e, 0x2d, 0xd4, 0x17, 0xd7, 0xbf, 0xf5, 0xa9, 0xf7,    
 0xc8, 0x8b, 0x3e, 0x71, 0x01, 0xa6, 0xac, 0x71, 0xe8, 0x8e, 0x2c, 0x50, 0xbb, 0x8e, 0x46, 0x1d,    
 0x62, 0x9c, 0xc2, 0xf6, 0x24, 0x22, 0xa7, 0x6a, 0xaa, 0x01, 0x77, 0x12, 0x4e, 0xff, 0x9f, 0x0e,    
 0xf4, 0x4b, 0xba, 0x3e, 0xde, 0xd0, 0xcf, 0x0d, 0x7c, 0x97, 0x9a, 0xe6, 0x46, 0xf1, 0x8a, 0x06,    
 0x01, 0x01, 0x00, 0x38, 0x27, 0xcf, 0x15, 0x2d, 0xc1, 0xda, 0xc8, 0x07, 0x3b, 0x5a, 0xa8, 0x70,    
 0xa7, 0x18, 0x34, 0x58, 0xa9, 0x1e, 0x40, 0xee, 0x5b, 0x33, 0x62, 0x78, 0x65, 0xd3, 0x68, 0x89,    
 0x0d, 0x5c, 0x96, 0x2d, 0x30, 0x34, 0x23, 0x22, 0xe0, 0x47, 0xa7, 0xba, 0x6b, 0x84, 0xfb, 0xce,    
 0x4f, 0x97, 0x40, 0x9b, 0x5f, 0xdf, 0x08, 0x8a, 0xd7, 0x38, 0xe4, 0x97, 0x06, 0x17, 0x02, 0x2b,    
 0x33, 0x7d, 0xb0, 0xc8, 0xfc, 0x3e, 0x01, 0x71, 0xb3, 0x73, 0x3f, 0x1e, 0x5b, 0x72, 0x92, 0x5d,    
 0xa2, 0xb1, 0xcd, 0x57, 0x46, 0x80, 0xfa, 0x98, 0x88, 0x85, 0xde, 0x48, 0xe4, 0xff, 0xf6, 0x0b,    
 0x3f, 0x28, 0xa2, 0x7e, 0x5d, 0x75, 0x3e, 0x79, 0xa2, 0xa6, 0x18, 0x83, 0xa7, 0x7b, 0x69, 0x1e,    
 0xa1, 0xf3, 0x33, 0x61, 0xe0, 0x5f, 0xc5, 0xfe, 0xbc, 0xd0, 0xaa, 0x1b, 0x67, 0x07, 0x33, 0xe5,    
 0x36, 0xac, 0xa8, 0x60, 0x79, 0x0c, 0x8e, 0x36, 0x6b, 0x4a, 0xf5, 0x32, 0xe4, 0x52, 0xfe, 0xdc,    
 0x95, 0xcb, 0xe0, 0xe9, 0x33, 0x80, 0x7d, 0xc8, 0xcc, 0xe3, 0x68, 0xb9, 0x8c, 0xf9, 0x24, 0x27,    
 0x77, 0x6b, 0x27, 0x3c, 0x6d, 0x7c, 0xeb, 0xc3, 0x25, 0xaa, 0x4a, 0xe8, 0xac, 0xa7, 0x4a, 0x3e,    
 0x87, 0x37, 0x15, 0xf5, 0x25, 0xe3, 0x1e, 0xce, 0x03, 0x4f, 0x7f, 0xed, 0xb0, 0x6a, 0x2b, 0xc7,    
 0x18, 0xb2, 0x8c, 0x32, 0x16, 0x7d, 0xe5, 0x93, 0xcb, 0xa5, 0xc2, 0xdc, 0x99, 0x93, 0x31, 0x9c,    
 0x58, 0x8d, 0xb6, 0x02, 0x5a, 0x4c, 0x3a, 0x68, 0xce, 0x0b, 0x5e, 0x0a, 0xc2, 0x68, 0x2a, 0xa7,    
 0x5e, 0x6c, 0x6c, 0x28, 0xf6, 0xc9, 0x40, 0x88, 0x51, 0x49, 0x7e, 0xa0, 0xee, 0xc7, 0x7b, 0x3c,    
 0xa9, 0x25, 0xad, 0x77, 0xc9, 0x84, 0x18, 0x61, 0x71, 0x7e, 0x20, 0xc1, 0x8c, 0x78, 0x21, 0xbd,    
 0xd1, 0x5f, 0x6d, 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00 };

    struct timeval ptm;
    gettimeofday(&ptm,NULL);

    pkthdr->ts.tv_sec = ptm.tv_sec;
    pkthdr->ts.tv_usec = ptm.tv_usec;
    pkthdr->caplen = sizeof(pkt_large);
    pkthdr->len    = sizeof(pkt_large);

    return pkt_large;
}

/*
 * start of serialized output code - first cut
 */

void pcap_queue_write(struct ll_queue *llq,
                      uint8_t *packet,
                      size_t length,
                      unsigned int sec,
                      unsigned int nsec) {

    if (llq->msgs[llq->widx].used == 0) {

        //char obuf[LLQ_MSG_SIZE];
        int olen = LLQ_MSG_SIZE;
        int ooff = 0;
        int trunc = 0;

        llq->msgs[llq->widx].ts.tv_sec = sec;
        llq->msgs[llq->widx].ts.tv_nsec = nsec;

        //obuf[sizeof(struct timespec)] = '\0';
        llq->msgs[llq->widx].buf[0] = '\0';

        if (packet && !length) {
            fprintf(stderr, "warning: attempt to write an empty packet\n");
        }

        /* note: we never perform byteswap when writing */
        struct pcap_packet_hdr packet_hdr;
        packet_hdr.ts_sec = sec;
        packet_hdr.ts_usec = nsec;
        packet_hdr.incl_len = length;
        packet_hdr.orig_len = length;

        // write the packet header
        int r = append_memcpy(llq->msgs[llq->widx].buf, &ooff, olen, &trunc, &packet_hdr, sizeof(packet_hdr));

        // write the packet
        r += append_memcpy(llq->msgs[llq->widx].buf, &ooff, olen, &trunc, packet, length);

        // f->bytes_written += length + sizeof(struct pcap_packet_hdr);
        // f->packets_written++;

        if ((trunc == 0) && (r > 0)) {

            llq->msgs[llq->widx].len = r;

            //fprintf(stderr, "DEBUG: sent a message!\n");
            __sync_synchronize(); /* A full memory barrier prevents the following flag set from happening too soon */
            llq->msgs[llq->widx].used = 1;

            //llq->next_write();
            llq->widx = (llq->widx + 1) % LLQ_DEPTH;
        }
    }
    else {
        //fprintf(stderr, "DEBUG: queue bucket used!\n");

        // TODO: this is where we'd update an output drop counter
        // but currently this spot in the code doesn't have access to
        // any thread stats pointer or similar and I don't want
        // to update a global variable in this location.
    }

}

