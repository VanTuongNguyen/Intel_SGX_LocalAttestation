#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>

# define MAX_PATH FILENAME_MAX
#include "sgx_tseal.h"
#include "sgx_report.h"
#include <sgx_urts.h>
#include "sample.h"
#include "sgx_quote.h"
#include "encl1_u.h"
#include "sgx_uae_service.h"



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid Intel(R) SGX device.",
        "Please make sure Intel(R) SGX module is enabled in the BIOS, and install Intel(R) SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "Intel(R) SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCL1_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_encl1_sample(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Changing dir to where the executable is.*/
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]),absolutePath);

    if( chdir(absolutePath) != 0)
    		abort();

    /* Initialize the enclave */
    if(initialize_enclave() < 0){

        return -1; 
    }
 
////////////////////////////////////////////////////////
//    int ecall_return = 0;
//
//
//
//    unsigned char mr_enclave[SGX_HASH_SIZE];
//    sgx_status_t ecall_ret = ecall_get_mr_enclave(global_eid, &ecall_return, mr_enclave);
//    if (ecall_ret != SGX_SUCCESS) {
//      printf("error\n");
//
//    }
//    for(int k=0;k< SGX_HASH_SIZE; k++)
//    	printf("%x",mr_enclave[k]);
///////////////////////////////////////////////////////////


////////////////////////////////////////////////////////


      sgx_target_info_t qe_info;
      sgx_epid_group_id_t p_gid;
      sgx_report_t report;
      sgx_spid_t spid;
      int ret;
      sgx_status_t ecall_ret;

     sgx_init_quote(&qe_info, &p_gid);
     memset(qe_info.reserved1, 0, sizeof qe_info.reserved1);
     memset(qe_info.reserved2, 0, sizeof qe_info.reserved2);
     ecall_ret = ecall_create_report(global_eid, &ret, &qe_info, &report);
     if (ecall_ret != SGX_SUCCESS || ret) {
       printf("ecall_create_report: ecall_ret=%x, ret=%x", ecall_ret, ret);
     }
     printf("GET REPORT SUCCESS\n");
/////////////////////////////////////////////
     unsigned char mr_enclave[32];
     memcpy(mr_enclave, report.body.mr_enclave.m, SGX_HASH_SIZE);
     for(int k=0;k< SGX_HASH_SIZE; k++)
     	printf("%x",mr_enclave[k]);
     printf("\nMR_ENCLAVE 1:\n");

     ///////////////////////////////
     uint8_t spid_tc[16] = {
         0x03, 0xD4, 0x81, 0x28,
         0x36, 0x6F, 0x1C, 0xD7,
         0x4F, 0xCA, 0x49, 0x0D,
         0x9B, 0x85, 0xB6, 0xAB,
     };

     memcpy(spid.id, spid_tc, sizeof spid_tc);
     for(int k=0;k<16;k++)
    	 printf("%x",spid.id[k]);
     uint32_t quote_size;
     sgx_calc_quote_size(NULL, 0, &quote_size);
     sgx_quote_t *quote = (sgx_quote_t *)(malloc(quote_size));

     ecall_ret = sgx_get_quote(&report,
                               SGX_LINKABLE_SIGNATURE,
                               &spid, NULL, NULL,
                               0, NULL, quote, quote_size);
     if (ecall_ret != SGX_SUCCESS)
       printf("error");
//////////////////////////////////////////////////////////
     printf("\nGET QUOTE SUCCESS\n");

//     printf("%u\n",quote_size);
//     for(int k=0;k< quote_size; k++)
//       	printf("%x",quote[k]);
//      printf(bufferToHex(mr_enclave,SGX_HASH_SIZE,1));
     //return ecall_return;

     unsigned char mr_enclave2[32];
     memcpy(mr_enclave2, quote->report_body.mr_enclave.m, SGX_HASH_SIZE);
     for(int k=0;k< SGX_HASH_SIZE; k++)
         printf("%x",mr_enclave2[k]);
          printf("\nMR_ENCLAVE 2:\n");


}
