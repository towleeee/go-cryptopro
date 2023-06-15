#include "gost.h"

extern int CreateContainer(BYTE prov, BYTE *container, BYTE *password) {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;

	if(!CryptAcquireContext(&hProv, container, NULL, prov, CRYPT_SILENT | CRYPT_NEWKEYSET)) {
		return 1;
	}

	CryptReleaseContext(hProv, 0);

	if(!CryptAcquireContext(&hProv, container, NULL, prov, CRYPT_NEWKEYSET)) {
		PRINT_ERROR("CreateContainer: CryptAcquireContext");
		return -1;
	}

	if(!CryptSetProvParam(hProv, PP_SIGNATURE_PIN, password, 0)) {
		PRINT_ERROR("CreateContainer: CryptSetProvParam");
		CryptReleaseContext(hProv, 0);
        return -2;
    }

	if(!CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey)) {
		PRINT_ERROR("CreateContainer: CryptGenKey");
		CryptReleaseContext(hProv, 0);
        return -3;
	}

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);

	return 0;
}

extern int OpenContainer(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *container, BYTE *password, DWORD keyType) {
	if (!CryptAcquireContext(hProv, container, NULL, prov, 0)) {
		PRINT_ERROR("OpenContainer: CryptAcquireContext");
		return -1;
	}

	if(!CryptSetProvParam(*hProv, PP_SIGNATURE_PIN, password, 0)) {
		PRINT_ERROR("OpenContainer: CryptSetProvParam");
		CryptReleaseContext(*hProv, 0);
        return -2;
    }

	if(!CryptGetUserKey(*hProv, keyType, hKey)) {
        PRINT_ERROR("OpenContainer: CryptGetUserKey");
		CryptReleaseContext(*hProv, 0);
        return -3;
    }

	return 0;
}

extern int CheckContainer(BYTE prov, BYTE *container, BYTE *password) {
	HCRYPTPROV hProv;
	
	if (!CryptAcquireContext(&hProv, container, NULL, prov, 0)) {
		PRINT_ERROR("CheckContainer: CryptAcquireContext");
		return -1;
	}

	if (!CryptSetProvParam(hProv, PP_SIGNATURE_PIN, password, 0)) {
		PRINT_ERROR("CheckContainer: CryptSetProvParam");
		CryptReleaseContext(hProv, 0);
		return -2;
	}

	CryptReleaseContext(hProv, 0);

	return 0;
}

extern BYTE *SignMessage(BYTE prov, BYTE *container, BYTE *password, BYTE *data, DWORD size, DWORD *dwSigLen, DWORD spec) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD hashtype;
	BYTE *output;

	switch (prov) {
		case PROV_GOST_2012_256:
			hashtype = CALG_GR3411_2012_256;
		break;
		case PROV_GOST_2012_512:
			hashtype = CALG_GR3411_2012_512;
		break;
	}

	if (!CryptAcquireContext(&hProv, container, NULL, prov, 0)) {
		PRINT_ERROR("SignMessage: CryptAcquireContext");
		return NULL;
	}

	if (!CryptSetProvParam(hProv, PP_SIGNATURE_PIN, password, 0)) {
		PRINT_ERROR("SignMessage: CryptSetProvParam");
		CryptReleaseContext(hProv, 0);
		return NULL;
	}

	if (!CryptCreateHash(hProv, hashtype, 0, 0, &hHash)) {
		PRINT_ERROR("SignMessage: CryptCreateHash");
		CryptReleaseContext(hProv, 0);
		return NULL;
	}

    if (!CryptHashData(hHash, data, size, 0)) {
		PRINT_ERROR("SignMessage: CryptHashData");
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return NULL;
	}

	if(!CryptSignHash(hHash, spec, NULL, 0, NULL, dwSigLen)) {
		PRINT_ERROR("SignMessage: CryptSignHash (1)");
		CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
		return NULL;
	}

	output = (BYTE*)malloc(sizeof(BYTE)*(*dwSigLen));

	if(!CryptSignHash(hHash, spec, NULL, 0, output, dwSigLen)) {
		PRINT_ERROR("SignMessage: CryptSignHash (2)");
		free(output);
		CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
		return NULL;
	}

	CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

	return output;
}

extern int VerifySign(BYTE prov, HCRYPTKEY *hKey, BYTE *sign, DWORD dwSigLen, BYTE *data, DWORD size) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD hashtype;

	switch (prov) {
		case PROV_GOST_2012_256:
			hashtype = CALG_GR3411_2012_256;
		break;
		case PROV_GOST_2012_512:
			hashtype = CALG_GR3411_2012_512;
		break;
	}

	if (!CryptAcquireContext(&hProv, NULL, NULL, prov, 0)) {
		PRINT_ERROR("VerifySign: CryptAcquireContext");
		return -2;
	}

	if (!CryptCreateHash(hProv, hashtype, 0, 0, &hHash)) {
		PRINT_ERROR("VerifySign: CryptCreateHash");
		CryptReleaseContext(hProv, 0);
		return -3;
	}

    if (!CryptHashData(hHash, data, size, 0)) {
		PRINT_ERROR("VerifySign: CryptHashData");
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return -4;
	}

	if(!CryptVerifySignature(hHash, sign, dwSigLen, *hKey, NULL, 0)) {
		// PRINT_ERROR("VerifySign: CryptVerifySignature");
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
        return 1;
    }

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return 0;
}

extern int ImportPublicKey(BYTE prov, HCRYPTPROV *hProv, HCRYPTKEY *hKey, BYTE *pkbytes, DWORD keyBlobLen) {
	if (!CryptAcquireContext(hProv, NULL, NULL, prov, 0)) {
		PRINT_ERROR("ImportPublicKey: CryptAcquireContext");
		return -1;
	}

	if (!CryptImportKey(*hProv, pkbytes, keyBlobLen, 0, 0, hKey)) {
		PRINT_ERROR("ImportPublicKey: CryptImportKey");
		CryptReleaseContext(*hProv, 0);
		return -2;
	}

	return 0;
}

extern BYTE *BytesPublicKey(HCRYPTKEY *hKey, DWORD *size) {
	BYTE *pkbytes;

	if(!CryptExportKey(*hKey, 0, PUBLICKEYBLOB, 0, NULL, size)) {
		PRINT_ERROR("BytesPublicKey: CryptExportKey (1)");
        return NULL;
    }

	pkbytes = (BYTE*)malloc(sizeof(BYTE)*(*size));

	if(!CryptExportKey(*hKey, 0, PUBLICKEYBLOB, 0, pkbytes, size)) {
		PRINT_ERROR("BytesPublicKey: CryptExportKey (2)");
		free(pkbytes);
        return NULL;
    }

	return pkbytes;
}
