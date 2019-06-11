#ifndef ENCL1_T_H__
#define ENCL1_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_report.h"
#include "sgx_tseal.h"
#include "sgx_quote.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_tuong_test(int a);
int ecall_encl1_sample(void);
int ecall_get_mr_enclave(unsigned char mr_enclave[32]);
int ecall_create_report(sgx_target_info_t* quote_enc_info, sgx_report_t* report);

sgx_status_t SGX_CDECL ocall_encl1_sample(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
