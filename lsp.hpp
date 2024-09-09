#pragma once

#include <stdio.h>
#include <string.h>

#include <vector>

namespace lsp
{

// TODO: Replace with real implementation once available, these are mocked
// values

inline std::vector<char>& getLsp()
{
    static std::vector<char> lspBuf = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    return lspBuf;
}

inline int passwordCallback(char* buf, int size, int, void*)
{
    std::vector<char>& pwd = getLsp();
    size_t pwdsz = static_cast<unsigned int>(size) < pwd.size()
                       ? static_cast<size_t>(size)
                       : static_cast<size_t>(pwd.size());
    memcpy(buf, pwd.data(), pwdsz);
    return pwdsz;
}

// This is required to avoid passphrase prompts in certain cases when using
// openssl APIs
inline int emptyPasswordCallback(char*, int, int, void*)
{
    return 0;
}

} // namespace lsp
