#pragma once 

#include <Windows.h>

//http://www.unknowncheats.me/forum/1064093-post3.html

bool CompareByteArray(PBYTE Data, PBYTE Signature)
{
	for (; *Signature; ++Signature, ++Data)
	{
		if (*Signature == '\x00')
		{
			continue;
		}
		if (*Data != *Signature)
		{
			return false;
		}
	}
	return true;
}

PBYTE FindSignature(PBYTE BaseAddress, DWORD ImageSize, PBYTE Signature)
{
	BYTE First = Signature[0];
	PBYTE Max = BaseAddress + ImageSize - strlen((PCHAR)Signature);

	for (; BaseAddress < Max; ++BaseAddress)
	{
		if (*BaseAddress != First)
		{
			continue;
		}
		if (CompareByteArray(BaseAddress, Signature))
		{
			return BaseAddress;
		}
	}
	return NULL;
}