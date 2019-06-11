#include "encl1_u.h"
#include <errno.h>

typedef struct ms_ecall_tuong_test_t {
	int ms_retval;
	int ms_a;
} ms_ecall_tuong_test_t;

typedef struct ms_ecall_encl1_sample_t {
	int ms_retval;
} ms_ecall_encl1_sample_t;

typedef struct ms_ecall_get_mr_enclave_t {
	int ms_retval;
	unsigned char* ms_mr_enclave;
} ms_ecall_get_mr_enclave_t;

typedef struct ms_ecall_create_report_t {
	int ms_retval;
	sgx_target_info_t* ms_quote_enc_info;
	sgx_report_t* ms_report;
} ms_ecall_create_report_t;

typedef struct ms_ocall_encl1_sample_t {
	const char* ms_str;
} ms_ocall_encl1_sample_t;

static sgx_status_t SGX_CDECL encl1_ocall_encl1_sample(void* pms)
{
	ms_ocall_encl1_sample_t* ms = SGX_CAST(ms_ocall_encl1_sample_t*, pms);
	ocall_encl1_sample(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_encl1 = {
	1,
	{
		(void*)encl1_ocall_encl1_sample,
	}
};
sgx_status_t ecall_tuong_test(sgx_enclave_id_t eid, int* retval, int a)
{
	sgx_status_t status;
	ms_ecall_tuong_test_t ms;
	ms.ms_a = a;
	status = sgx_ecall(eid, 0, &ocall_table_encl1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_encl1_sample(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_encl1_sample_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_encl1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_mr_enclave(sgx_enclave_id_t eid, int* retval, unsigned char mr_enclave[32])
{
	sgx_status_t status;
	ms_ecall_get_mr_enclave_t ms;
	ms.ms_mr_enclave = (unsigned char*)mr_enclave;
	status = sgx_ecall(eid, 2, &ocall_table_encl1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_create_report(sgx_enclave_id_t eid, int* retval, sgx_target_info_t* quote_enc_info, sgx_report_t* report)
{
	sgx_status_t status;
	ms_ecall_create_report_t ms;
	ms.ms_quote_enc_info = quote_enc_info;
	ms.ms_report = report;
	status = sgx_ecall(eid, 3, &ocall_table_encl1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

