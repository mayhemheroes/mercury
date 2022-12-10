#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

std::string get_domain_name(char* server_name);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    char* cstr = strdup(str.c_str());
    get_domain_name(cstr);
    free(cstr);

    return 0;
}