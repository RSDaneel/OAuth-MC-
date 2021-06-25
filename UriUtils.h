//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unit......:		UriUtils.h
// Written By:		Reinhard Daneel
// Purpose...:		Provide Utilities for URI RFC3986 Encoding

// Change Control:					
// ---------------					
// RS Daneel	v1.0.0.0	2020-04-09	Initial
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#pragma once
#include <string>
#include <stdexcept>

//RFC 3986

using namespace std;

namespace Utils
{
    static class UriUtils
    {
    private:       
        static constexpr const char* HexUpperChars = "0123456789ABCDEF";

        static void EscapeAsciiChar(char ch, char to[3])
        {
            int pos = 0;
            to[pos++] = '%';
            to[pos++] = HexUpperChars[((ch & 0xf0) >> 4)];
            to[pos++] = HexUpperChars[(ch & 0xf)];
        }

    public:
        static string HexEscape(char character)
        {
            if (character > 0xff)
            {
                throw std::out_of_range((char*)character);
            }
            auto chars = new char[3];
            EscapeAsciiChar(character, chars);
            return string(chars, 3);
        }

        static string UrlEncode(const string& value) 
        {

        }
    };

}