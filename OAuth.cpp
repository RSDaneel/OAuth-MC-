//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unit......:		OAuth.cpp
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

#include "stdafx.h"
#include "OAuth.h"
#include "UriUtils.h"
#include <string>

#include <windows.h>
#include <vector>
#include <map>
#include <algorithm>

#include <openssl\pkcs12.h>
#include <openssl\err.h>
#include <openssl\applink.c>
#include <openssl\pem.h>
#include <openssl\sha.h>
#include <openssl\rsa.h>
#include <openssl\evp.h>
#include <openssl\rand.h>
#include <assert.h>
#include <iostream>
#include <stdlib.h>

#include <ctime>
#include <random>

void OAuthUtil::ToUpper(string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}

char* OAuthUtil::EncodeBase64(const unsigned char* input, int length) {
    const auto pl = 4 * ((length + 2) / 3);
    auto output = reinterpret_cast<char*>(calloc(pl + 1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
    const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output), input, length);
    if (pl != ol) { std::cerr << "Whoops, encode predicted " << pl << " but we got " << ol << "\n"; }
    return output;
}

unsigned char* OAuthUtil::DecodeBase64(const char* input, int length) {
    const auto pl = 3 * length / 4;
    auto output = reinterpret_cast<unsigned char*>(calloc(pl + 1, 1));
    const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char*>(input), length);
    if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
    return output;
}

void OAuthUtil::Sha256_hash(char* str, unsigned char* outputBuffer[SHA256_DIGEST_LENGTH])
{
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(*outputBuffer, &sha256);
}

void OAuthUtil::FindAndReplaceAll(string& data, string tosearch, string replacestr)
{
    // Get the first occurrence
    size_t Pos = data.find(tosearch);

    // Repeat till end is reached
    while (Pos != string::npos)
    {
        // Replace this occurrence of Sub String
        data.replace(Pos, tosearch.size(), replacestr);
        // Get the next occurrence from the current position
        Pos = data.find(tosearch, Pos + replacestr.size());
    }
}

OAuth::OAuth()
{
    _IsKeyFound = false;
}

OAuth::OAuth(string keypath, string keyalias, string keypass)
{
    _KeyPath = keypath;
    _KeyAlias = keyalias;
    _KeyPassword = keypass;
    _IsKeyFound = KeyFileExists();
}

OAuth::~OAuth()
{

}

string OAuth::GetAuthorizationHeader(string uri, string method, string payload, string consumerKey)
{
    auto QueryParameters = ExtractQueryParams(uri);
    auto OAuthParameters = std::map<string, string>
    {
        { "oauth_consumer_key", consumerKey },
        { "oauth_nonce", GetNonce() },
        { "oauth_timestamp", GetTimestamp() },
        { "oauth_signature_method", "RSA-SHA256" },
        { "oauth_version", "1.0" },
        { "oauth_body_hash", GetBodyHash(payload) }
    };

    // Compute the OAuth signature
    auto OAuthParamString = GetOAuthParamString(QueryParameters, OAuthParameters);
    auto BaseUri = GetBaseUriString(uri);
    auto SignatureBaseString = GetSignatureBaseString(BaseUri, method, OAuthParamString);

    //TESTING
    auto Signature = SignSignatureBaseString(SignatureBaseString/*, encoding, signingKey*/);
    OAuthParameters.insert(std::pair<string, string>("oauth_signature", Signature));

    // Constructs and returns a valid Authorization header as per https://tools.ietf.org/html/rfc5849#section-3.5.1
    string AuthHeader = "";
    for (auto param : OAuthParameters)
    {
        AuthHeader += AuthHeader.size() == 0 ? "OAuth " : ",";
        AuthHeader += param.first;
        AuthHeader += "=\"";
        if (param.first == "oauth_consumer_key")
        {
            AuthHeader += param.second;
        }
        else
        {
            AuthHeader += ToUriRfc3986(param.second);
        }
        AuthHeader += "\"";
    }
    return AuthHeader;
}

map<string, vector<string>> OAuth::ExtractQueryParams(string uri)
{
    map<string, vector<string>> Params;
    int SeparatorIndex = -1;
    string Key, Value, EncodedKey, EncodedValue, QueryParam;

    int BeginIndex = uri.find('?');
    if (BeginIndex >= 0)
    {
        auto RawQueryString = uri.substr(BeginIndex);
        //SHOULD ADD THIS EVENTUALLY - RS Daneel
        //auto decodedQueryString = Uri.UnescapeDataString(rawQueryString);
        //bool mustEncode = !decodedQueryString.Equals(rawQueryString);
        char Delimeters[] = "&?";
        char* Token;
        Token = strtok((char*)RawQueryString.c_str(), Delimeters);
        while (Token != NULL)
        {  
            //std::string QueryParam = Token;
            QueryParam = Token;
            SeparatorIndex = QueryParam.find('=');
            Key = QueryParam.substr(0, SeparatorIndex);//SeparatorIndex < 0 ? QueryParam : Uri.UnescapeDataString(QueryParam.Substring(0, SeparatorIndex));
            Value = QueryParam.substr(SeparatorIndex + 1);//SeparatorIndex < 0 ? "" : Uri.UnescapeDataString(QueryParam.Substring(SeparatorIndex + 1));
            EncodedKey = Key;//mustEncode ? ToUriRfc3986(key) : key;
            EncodedValue = Value;//mustEncode ? ToUriRfc3986(value) : value;
            map<string, vector<string>>::iterator it = Params.find(Key);
            if (it != Params.end())
            {
                it->second.push_back(EncodedValue);
            }
            else
            {
                vector<string> Temp;
                Temp.push_back(EncodedValue);
                Params.insert(Params.end(), pair<string, vector<string>>(Key, Temp));
            }
            
            Token = strtok(NULL, Delimeters);
        }
    }

    return Params;
}

string OAuth::GetOAuthParamString(map<string, vector<string>> queryparam, map<string, string> oauthparams)
{
    string paramstr = "";
    map<string, vector<string>> SortedParameters = queryparam;//Should sort the map eventually - RSDaneel
    
    // Build the OAuth parameter string 
    for (auto param : oauthparams)
    {
        paramstr += (paramstr.size()) > 0 ? "&" : "";
        paramstr += param.first;
        paramstr += "=";
        paramstr += param.second;
    }

    for (auto param : SortedParameters)
    {
        paramstr += (paramstr.size()) > 0 ? "&" : "";
        paramstr += param.first;
        paramstr += "=";
        paramstr += param.second[0];//only use the first value
    }
    return paramstr;
}

string OAuth::GetBaseUriString(string uri)
{
    string BaseURI = "";
    //Implement URI to BASE
    int BeginIndex = uri.find('?');
    BaseURI = uri.substr(0,BeginIndex);
    return BaseURI;
}

string OAuth::GetSignatureBaseString(string baseuri, string method, string oauthparamsstr)
{
    string basestring = "";
    OAuthUtil::ToUpper(method);                                    // Uppercase HTTP method
    basestring += method;
    basestring += "&" + ToUriRfc3986(baseuri);          // Base URI
    basestring += "&" + ToUriRfc3986(oauthparamsstr);   // OAuth parameter string

    return basestring;
}

string OAuth::GetNonce()
{
    const int NonceSize = 16;
    char Nonce[NonceSize] = {};
    //RANDOM NUMBERS
    std::random_device rd;
    std::mt19937 Rng; //mersenne_twister_engine
    uint32_t seed_val;

    int Rand = 0;
    std::uniform_int_distribution<uint32_t> uint_dist16(0, 16); // range [0,9]

    for (int idx = 0; idx < NonceSize; ++idx)
    {
        char Hexadec_n[16];
        Rng.seed(rd());
        Rand = uint_dist16(Rng);
            
        itoa(Rand, Hexadec_n, 16);
        Nonce[idx] = Hexadec_n[0];
    }
//// RANDOM BYTES
//int rc = RAND_bytes((unsigned char*)Nonce, sizeof(Nonce));
//unsigned long err = ERR_get_error();

//if (rc != 1) {
//    // RAND_bytes failed
//    //`err` is valid
//}

    return string((char*)Nonce, NonceSize);
}

string OAuth::GetTimestamp()
{
    std::time_t Tick = std::time(0);
    
    return std::to_string(Tick);
}

string OAuth::GetBodyHash(string payload, string charset)
{
    unsigned char* sha = new unsigned char[65];
    //Compute hash from payload
    OAuthUtil::Sha256_hash((char*)payload.c_str(), &sha);
    char *output = OAuthUtil::EncodeBase64(sha, SHA256_DIGEST_LENGTH);

    return string(output);
}

//---------------------------------------------------------------------
// LoadSigningKey - can be expanded for other container types
// Only uses .p12 at the moment
//---------------------------------------------------------------------
RSAInfo OAuth::LoadSigningKey(char* Filename, char* Password)
{
    RSAInfo Container;
    Container.ca = NULL;
    PKCS12* p12;
    FILE* fp;

    //LOAD KEY
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!(fp = fopen(Filename, "rb"))) {
        fprintf(stderr, "Error opening file %s\n", Filename);
        throw exception("Certificate failed to load", 1);
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        throw exception("p12 failed to load", 1);
    }
    if (!PKCS12_parse(p12, Password/*"keystorepassword"*/, &Container.pkey, &Container.cert, &Container.ca)) {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        throw exception("p12  failed to parse", 1);
    }
    PKCS12_free(p12);

    return Container;
}

string OAuth::SignSignatureBaseString(string baseString/*, Encoding encoding, RSA privateKey*/)
{
    PKCS12* p12;
    FILE* fp;
    EVP_PKEY_CTX* ctx;
    /* md is a SHA-256 digest in this example. */
    unsigned char* sha, * sig;
    size_t shalen = 32, siglen;

    //LOAD KEY
    RSAInfo KeyInfo = LoadSigningKey((char*)_KeyPath.c_str(), (char*)_KeyPassword.c_str());

    //Get SHA256 Hash
    char* OAuthParamString = (char*)baseString.c_str();
    unsigned char* output = new unsigned char[SHA256_DIGEST_LENGTH];
    OAuthUtil::Sha256_hash(OAuthParamString, &output);
      
    //SignHash
    /*
     * NB: assumes signing_key and md are set up before the next
     * step. signing_key must be an RSA private key and md must
     * point to the SHA-256 digest to be signed.
     */
    ctx = EVP_PKEY_CTX_new(KeyInfo.pkey, NULL /* no engine */);
    if (!ctx) {
        /* Error occurred */
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        /* Error */
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        /* Error */
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        /* Error */
    }

    /* Determine buffer length */
   if (EVP_PKEY_sign(ctx, NULL, &siglen, (unsigned char*)output, SHA256_DIGEST_LENGTH) <= 0) {
        /* Error */
    }
    sig = (unsigned char*)OPENSSL_malloc(siglen);

    if (!sig)
    {  
        /* malloc failure */
    }
    if (EVP_PKEY_sign(ctx, sig, &siglen, (unsigned char*)output, SHA256_DIGEST_LENGTH) <= 0)
    {
        /* Error */
        /* Signature is siglen bytes written to buffer sig */
    }

    //Base64 encode result
    char* Base64Sign = OAuthUtil::EncodeBase64(sig, siglen);

    EVP_PKEY_free(KeyInfo.pkey);
    EVP_PKEY_CTX_free(ctx);

    return Base64Sign;
}

string OAuth::ToUriRfc3986(string input)
{
    string Escape = "";
    if (input != "")
    {
        Escape = input;
        //char UriRfc3986EscapedChars[] = { '!', '*', '\'', '(', ')' };
        //NOTE: '%' should always be replaced first RFC3986 uses % to mark the start of a escape char
        char UriRfc3986EscapedChars[] = { '%', '!', '#', '$','&', '\'', '(', ')', '*', '+', ',', '/', ':', ';', '=', '?', '@', '[', ']' };
        for (auto EscapedChar : UriRfc3986EscapedChars)
        {
            OAuthUtil::FindAndReplaceAll(Escape, string(1, EscapedChar), Utils::UriUtils::HexEscape(EscapedChar));
        }

    }

    return Escape;
}

bool OAuth::IsKeyFound()
{
    return _IsKeyFound;
}

bool  OAuth::KeyFileExists()
{
    FILE* fp;
    if (!(fp = fopen((char*)_KeyPath.c_str(), "rb")))
    {
        return false;
    }
    fclose(fp);
    return true;
}