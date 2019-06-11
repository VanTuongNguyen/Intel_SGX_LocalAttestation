#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <sgx_report.h>
#include <sgx_quote.h>
#include "sgx_tseal.h"
#include "encl1.h"
#include "encl1_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_encl1_sample(buf);
}

int ecall_encl1_sample()
{
  printf("IN ENCL1\n");
  return 0;
}

int ecall_tuong_test(int a)
{
	printf("TUONG TEST SUCCESS\n %d", a);
	return 0;
}
int ecall_get_mr_enclave(unsigned char mr_enclave[32]) {
  sgx_report_t report;

  sgx_status_t ret = sgx_create_report(NULL, NULL, &report);
  if (ret != SGX_SUCCESS) {
    printf("failed to get mr_enclave\n");
    return -1;
  }

  memcpy(mr_enclave, report.body.mr_enclave.m, SGX_HASH_SIZE);

  return 0;
}

int ecall_create_report (sgx_target_info_t* quote_enc_info, sgx_report_t* report)
{
    sgx_report_data_t data;
    int ret = 0;
    memset( &data.d, 0x88, sizeof data.d); // random data
    ret = sgx_create_report(quote_enc_info, &data, report);
    return ret;
}
