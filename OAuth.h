//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unit......:		OAuth.h
// Written By:		Reinhard Daneel
// Purpose...:		Provide OAuth 1.0a implementation with crypto using OpenSSL
//                  OAuth signed using SHA256 hash with X509 Cert
//                  Loading of PKCS12 Keystore
//                  This is specifically built to be used with the MasterCom API
// Change Control:					
// ---------------					
// RS Daneel	v1.0.0.0	2020-03-01	Initial
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#pragma once
#include <string>
#include <vector>
#include <map>
#include <openssl\rsa.h>
#include <openssl\evp.h>
#include <openssl\sha.h>

using namespace std;


struct RSAInfo
{
    X509* cert;
    EVP_PKEY* pkey;
    STACK_OF(X509)* ca;
};

static class OAuthUtil
{
public:
    static void             ToUpper(string& str);
    static char*            EncodeBase64(const unsigned char* input, int length);
    static unsigned char*   DecodeBase64(const char* input, int length);
    static void             Sha256_hash(char* str, unsigned char* outputBuffer[SHA256_DIGEST_LENGTH]);
    static void             FindAndReplaceAll(string& data, string tosearch, string replacestr);
};

class OAuth
{
private:
    string _KeyPath;
    string _KeyAlias;
    string _KeyPassword;
    bool _IsKeyFound;
    
    bool KeyFileExists();
public:
    OAuth();
    OAuth(string keypath, string keyalias, string keypass);
    ~OAuth();

    RSAInfo                     LoadSigningKey(char* Filename, char* Password);
    string                      SignSignatureBaseString(string baseString/*, Encoding encoding, RSA privateKey*/);
    map<string, vector<string>> ExtractQueryParams(string uri);
    string                      GetAuthorizationHeader(string uri, string method, string payload, string consumerKey);
    string                      GetOAuthParamString(map<string, vector<string>> queryparam, map<string, string> oauthparams);
    string                      GetBaseUriString(string uri);
    string                      GetSignatureBaseString(string baseuri, string method, string oauthparamsstr);
    string                      GetNonce();
    string                      GetTimestamp();
    string                      GetBodyHash(string payload, string charset = "utf-8");
    string                      ToUriRfc3986(string input);
    bool                        IsKeyFound();
};