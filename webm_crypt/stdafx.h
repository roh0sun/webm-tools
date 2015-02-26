
#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>

// Win32 Crypto
#pragma comment(lib, "crypt32.lib")

// Crypto++
#pragma comment(lib, "cryptlib.lib")
