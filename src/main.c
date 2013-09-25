#include "stdlib.h"
#include "pcap.h"
#include "string.h"

/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 

  int i=0, *counter = (int *)arg; 

  printf("Packet Count: %d\n", ++(*counter)); 
  printf("Received Packet Size: %d\n", pkthdr->len); 
  printf("Payload:\n"); 
  for (i=0; i<pkthdr->len; i++){ 

         if ( isprint(packet[i]) ) /* If it is a printable character, print it */
                 printf("%c ", packet[i]); 
         else 
                 printf(". "); 
                                 
         if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
                printf("\n"); 
  } 
  
        return; 
} 




int main(int arg_count,char* argv[]){


        char *nwi_name = NULL;
        pcap_t *ss_handle = NULL;
        
        char errbuf[PCAP_ERRBUF_SIZE];
        memset(errbuf,0,PCAP_ERRBUF_SIZE); 
        // fill up first PCAP_ERRBUF_SIZE num of bytes with 0's

        struct bpf_program fp;
        char filter_exp[] = "port 23";
        bpf_u_int32 mask;
        bpf_u_int32 net;

        if(arg_count>1)
                nwi_name= argv[1];

        else{
                printf("\nprovide a network interface name as argument!");
                printf("\nUse $ifconfig to find network interfaces...\n\n");
                return -1;
        }

        /* pcap_open_live() => func prototype
            pcap_t *pcap_open_live(char *device, int max_cap_len, int promisc, int timeout,
                  char *ebuf)
                  max_cap_len => BUFSIZ
                  promisc => 0-non-promisc ; 1-promisc
                  ebuf => error msg (string)
        *
        */
        ss_handle = pcap_open_live(nwi_name,BUFSIZ,1,1024,errbuf);
        // BUFSIZ => 2^13 ( 8192 )
       

        // check if the dev is opened properly...
        if(ss_handle = NULL){
                printf("\nOpening the interface %s failed!\n",nwi_name);
                return -1;
        }
        // else
        printf("\nDevice opened successfully!\n");


        // lets compile a filter
        /*
         * $$Function Prototype$$
         * int pcap_compile(pcap_t *handle, struct bpf_program *fp, char *str, int optimize,
                 bpf_u_int32 netmask)
                 - bpf_program => compiled filter
                 - str => filter expression
                 - optimize => boolean 
                 - netmask => 
         *
         */
       /* 
        if( pcap_compile(ss_handle,&fp,filter_exp,0,net) == -1){
                printf("\nProblem with filter compilation\n\n");
                return -1;
        }
        printf("\nFilter compiled successfully!\n");
                       
        // Setting the filter
        /*
         * $$Function Prototype$$
         * int pcap_setfilter(pcap_t *handle, struct bpf_program *fp)
         
         */
        /*
        if( pcap_setfilter(ss_handle,&fp) == -1){
                printf("\nProblem with setting filter\n\n");
                return -1;
        }
        printf("\nSetting filter successful!\n");
        */

        int count = 0;
         /* Loop forever & call processPacket() for every received packet*/ 
        if ( pcap_loop(ss_handle, -1, processPacket, (u_char *)&count) == -1){
                fprintf(stderr, "ERROR: %s\n", pcap_geterr(ss_handle) );
                exit(1);
        }

        return 0;
}
