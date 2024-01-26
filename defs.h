#include "structs.h"

#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }
#define FILL_STRING(string, buffer)       \
	string.Length = (USHORT)strlen(buffer);   \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer
