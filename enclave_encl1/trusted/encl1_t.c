#include "encl1_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_tuong_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_tuong_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_tuong_test_t* ms = SGX_CAST(ms_ecall_tuong_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_tuong_test(ms->ms_a);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encl1_sample(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encl1_sample_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encl1_sample_t* ms = SGX_CAST(ms_ecall_encl1_sample_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_encl1_sample();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_mr_enclave(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_mr_enclave_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_mr_enclave_t* ms = SGX_CAST(ms_ecall_get_mr_enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_mr_enclave = ms->ms_mr_enclave;
	size_t _len_mr_enclave = 32 * sizeof(unsigned char);
	unsigned char* _in_mr_enclave = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mr_enclave, _len_mr_enclave);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mr_enclave != NULL && _len_mr_enclave != 0) {
		if ( _len_mr_enclave % sizeof(*_tmp_mr_enclave) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mr_enclave = (unsigned char*)malloc(_len_mr_enclave)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mr_enclave, 0, _len_mr_enclave);
	}

	ms->ms_retval = ecall_get_mr_enclave(_in_mr_enclave);
	if (_in_mr_enclave) {
		if (memcpy_s(_tmp_mr_enclave, _len_mr_enclave, _in_mr_enclave, _len_mr_enclave)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_mr_enclave) free(_in_mr_enclave);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_report_t* ms = SGX_CAST(ms_ecall_create_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_quote_enc_info = ms->ms_quote_enc_info;
	size_t _len_quote_enc_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_quote_enc_info = NULL;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;

	CHECK_UNIQUE_POINTER(_tmp_quote_enc_info, _len_quote_enc_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_quote_enc_info != NULL && _len_quote_enc_info != 0) {
		_in_quote_enc_info = (sgx_target_info_t*)malloc(_len_quote_enc_info);
		if (_in_quote_enc_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_quote_enc_info, _len_quote_enc_info, _tmp_quote_enc_info, _len_quote_enc_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}

	ms->ms_retval = ecall_create_report(_in_quote_enc_info, _in_report);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_quote_enc_info) free(_in_quote_enc_info);
	if (_in_report) free(_in_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_tuong_test, 0},
		{(void*)(uintptr_t)sgx_ecall_encl1_sample, 0},
		{(void*)(uintptr_t)sgx_ecall_get_mr_enclave, 0},
		{(void*)(uintptr_t)sgx_ecall_create_report, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][4];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_encl1_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_encl1_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_encl1_sample_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_encl1_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_encl1_sample_t));
	ocalloc_size -= sizeof(ms_ocall_encl1_sample_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

