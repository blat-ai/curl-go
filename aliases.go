package curlgo

// Conventional Go spellings for frequently used curl constants.
const (
	OptFile                    = OptWriteData
	OptInfile                  = OptReadData
	OptWriteHeader             = OptHeaderData
	CurlOpt_FILE               = OptFile
	CurlOpt_INFILE             = OptInfile
	CurlOpt_WRITEHEADER        = OptWriteHeader
	InfoHTTPCode               = InfoResponseCode
	CurlInfo_HTTP_CODE         = InfoHTTPCode
	SSLVersionTLS1_0           = CurlSslVersion_TLSv1_0
	SSLVersionTLS1_1           = CurlSslVersion_TLSv1_1
	SSLVersionTLS1_2           = CurlSslVersion_TLSv1_2
	SSLVersionTLS1_3           = CurlSslVersion_TLSv1_3
	OptSSLVerifyPeer           = CurlOpt_SSL_VERIFYPEER
	OptSSLVerifyHost           = CurlOpt_SSL_VERIFYHOST
	OptSSLVerifyStatus         = CurlOpt_SSL_VERIFYSTATUS
	OptInfileSizeLarge         = CurlOpt_INFILESIZE_LARGE
	OptPostFieldsSize          = CurlOpt_POSTFIELDSIZE
	OptPostFieldsSizeLarge     = CurlOpt_POSTFIELDSIZE_LARGE
	OptSSLEnableALPN           = CurlOpt_SSL_ENABLE_ALPN
	OptSSLEnableNPN            = CurlOpt_SSL_ENABLE_NPN
	OptSSLFalseStart           = CurlOpt_SSL_FALSESTART
	HTTPVersion1_0             = CurlHttpVersion_V1_0
	HTTPVersion1_1             = CurlHttpVersion_V1_1
	HTTPVersion2               = CurlHttpVersion_V2_0
	HTTPVersion2TLS            = CurlHttpVersion_V2TLS
	HTTPVersion2PriorKnowledge = CurlHttpVersion_V2_PRIOR_KNOWLEDGE
	HTTPVersion3               = CurlHttpVersion_V3
	HTTPVersion3Only           = CurlHttpVersion_V3ONLY
)
