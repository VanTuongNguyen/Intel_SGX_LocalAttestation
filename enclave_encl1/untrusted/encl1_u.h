#ifndef ENCL1_U_H__
#define ENCL1_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "sgx_tseal.h"
#include "sgx_quote.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_ENCL1_SAMPLE_DEFINED__
#define OCALL_ENCL1_SAMPLE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_encl1_sample, (const char* str));
#endif

sgx_status_t ecall_tuong_test(sgx_enclave_id_t eid, int* retval, int a);
sgx_status_t ecall_encl1_sample(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_get_mr_enclave(sgx_enclave_id_t eid, int* retval, unsigned char mr_enclave[32]);
sgx_status_t ecall_create_report(sgx_enclave_id_t eid, int* retval, sgx_target_info_t* quote_enc_info, sgx_report_t* report);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
