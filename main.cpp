#include "stdafx.h"

_NT_BEGIN

HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags) 
{
	*Version = DEBUG_EXTENSION_VERSION(1, 0);
	*Flags = 0; 
	return S_OK;
}

void CALLBACK DebugExtensionUninitialize()
{
}

HRESULT CALLBACK DebugExtensionCanUnload()
{
	return S_OK;
}

void CALLBACK DebugExtensionUnload()
{
}

#define EXTEND64(pv) ((ULONG64)(LONG_PTR)(pv))

PVOID AccessResource(_In_ PVOID hmod, _In_ PCWSTR pri[], _In_ DWORD level, _Out_opt_ PDWORD pcb)
{
	if (pcb) *pcb = 0;

	if (!level) return 0;

	DWORD size;
	PVOID resBase = RtlImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size);

	PIMAGE_RESOURCE_DIRECTORY pird = (PIMAGE_RESOURCE_DIRECTORY)resBase;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pirde, _pirde;
	PIMAGE_RESOURCE_DATA_ENTRY pde = 0;
	DWORD Offset;
	do 
	{
		if (!pird) return 0;
		pirde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pird + 1);
		DWORD a = 0, b = pird->NumberOfNamedEntries, o;

		PCWSTR Id = *pri++;
		BOOL Named = TRUE;
		if (IS_INTRESOURCE(Id))
		{
			Named = FALSE;
			pirde += pird->NumberOfNamedEntries;
			b = pird->NumberOfIdEntries;
		}

		if (!b || ((ULONG_PTR)(pirde + b) - (ULONG_PTR)resBase) >= size) return 0;

		do 
		{
			int i;

			_pirde = &pirde[o = (a + b) >> 1];

			if (Named)
			{
				if (!_pirde->NameIsString) return 0;

				PIMAGE_RESOURCE_DIR_STRING_U pu = (PIMAGE_RESOURCE_DIR_STRING_U)
					RtlOffsetToPointer(resBase, _pirde->NameOffset);

				UNICODE_STRING us1, us2 = { pu->Length * sizeof(WCHAR), us2.Length, pu->NameString };
				RtlInitUnicodeString(&us1, Id);

				i = RtlCompareUnicodeString(&us1, &us2, FALSE);
			}
			else
			{
				if (_pirde->NameIsString) return 0;
				i = Id ? (ULONG)(ULONG_PTR)Id - _pirde->Id : 0;
			}

			if (!i) break;

			if (i < 0) b = o; else a = o + 1;

		} while(a < b);

		if (b <= a) return 0;

		if (_pirde->DataIsDirectory) 
		{
			Offset = _pirde->OffsetToDirectory;
			if ((size <= Offset) || 
				(size - Offset < sizeof (IMAGE_RESOURCE_DIRECTORY))) return 0;
			pird = (PIMAGE_RESOURCE_DIRECTORY)RtlOffsetToPointer(resBase, Offset);
		}
		else 
		{
			Offset = _pirde->OffsetToData;
			if ((size <= Offset) || 
				(size - Offset < sizeof (IMAGE_RESOURCE_DATA_ENTRY))) return 0;
			pde = (PIMAGE_RESOURCE_DATA_ENTRY )RtlOffsetToPointer(resBase, Offset);
			pird = 0;
		}

	} while(--level);

	if (!pde) return 0;

	*pcb = pde->Size;

	return (PBYTE)hmod + pde->OffsetToData;
}

struct _MI 
{
	IDebugDataSpaces2* pDataSpace;
	ULONG_PTR pRemoteBase;
	ULONG_PTR ImageBase;
	ULONG ImageSize;
	BOOL bFail;
};

#include "../inc/rtlframe.h"

typedef struct RTL_FRAME<_MI> MI;

LONG NTAPI OnVex(::PEXCEPTION_POINTERS pep)
{
	::PEXCEPTION_RECORD ExceptionRecord = pep->ExceptionRecord;

	if (STATUS_ACCESS_VIOLATION == ExceptionRecord->ExceptionCode &&
		1 < ExceptionRecord->NumberParameters &&
		0 == ExceptionRecord->ExceptionInformation[0])
	{
		if (_MI* p = MI::get())
		{
			ULONG_PTR addr = ExceptionRecord->ExceptionInformation[1];
			union {
				ULONG_PTR offset;
				LARGE_INTEGER ByteOffset;
			};

			ULONG_PTR ImageBase = p->ImageBase;
			offset = addr - ImageBase;

			if (offset < p->ImageSize)
			{
				SIZE_T s = 1;
				if (0 <= ZwAllocateVirtualMemory(NtCurrentProcess(), (void**)&addr, 0, &s, MEM_COMMIT, PAGE_READWRITE))
				{
					offset = addr - p->ImageBase;

					ULONG cb;
					p->pDataSpace->ReadVirtual(p->pRemoteBase + offset, (PBYTE)ImageBase + offset, (ULONG)s, &cb);

					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
RtlImageNtHeaderEx(
				   _In_ ULONG Flags,
				   _In_ PVOID BaseOfImage,
				   _In_ ULONG64 Size,
				   _Out_ PIMAGE_NT_HEADERS *OutHeaders
				   );

struct VS_VERSIONINFO_HEADER {
	WORD             wLength;
	WORD             wValueLength;
	WORD             wType;
	WCHAR            szKey[];
};

const VS_FIXEDFILEINFO* GetFileVersion(VS_VERSIONINFO_HEADER* pv, ULONG size)
{
	ULONG wLength, wValueLength;

	if (size > sizeof(VS_VERSIONINFO_HEADER) &&
		(wLength = pv->wLength) >= sizeof(VS_VERSIONINFO_HEADER) &&
		(wValueLength = pv->wValueLength) >= sizeof(VS_FIXEDFILEINFO) &&
		wLength <= size &&
		wValueLength <= (wLength - sizeof(VS_VERSIONINFO_HEADER))
		)
	{
		PVOID end = RtlOffsetToPointer(pv, wLength - wValueLength);
		PCWSTR sz = pv->szKey;
		do 
		{
			if (!*sz++)
			{
				VS_FIXEDFILEINFO* pffi = (VS_FIXEDFILEINFO*)((__alignof(VS_FIXEDFILEINFO) - 1 + (ULONG_PTR)sz) & ~(__alignof(VS_FIXEDFILEINFO) - 1));
				return VS_FFI_SIGNATURE == pffi->dwSignature ? pffi : 0;
			}
		} while (sz <= end);
	}

	return 0;
}

void DumpVersion(IDebugControl* pDebugControl, IDebugDataSpaces2* pDataSpace, PVOID RemoteBase, ULONG ImageSize)
{
	if (PVOID ImageBase = VirtualAlloc(0, ImageSize, MEM_RESERVE, PAGE_READWRITE))
	{
		MI m;
		m.pRemoteBase = (ULONG_PTR)RemoteBase;
		m.ImageBase = (ULONG_PTR)ImageBase;
		m.ImageSize = ImageSize;
		m.pDataSpace = pDataSpace;
		m.bFail = FALSE;

		PIMAGE_NT_HEADERS pinth;
		
		if (0 <= RtlImageNtHeaderEx(0, ImageBase, ImageSize, &pinth))
		{
			LARGE_INTEGER time;
			TIME_FIELDS tf;
			RtlSecondsSince1970ToTime(pinth->FileHeader.TimeDateStamp, &time);
			RtlTimeToTimeFields(&time, &tf);

			pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "\t%08x: %u-%02u-%02u %02u:%02u:%02u\n", 
				pinth->FileHeader.TimeDateStamp, tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);

			ULONG cb;

			PCWSTR a[] = { RT_VERSION, MAKEINTRESOURCEW(1), 0 };

			union {
				PVOID pv;
				VS_VERSIONINFO_HEADER* pvv;
			};

			if ((pv = AccessResource(ImageBase, a, _countof(a), &cb)) && !m.bFail)
			{
				pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%p %x\n", pv, cb);

				if (const VS_FIXEDFILEINFO* pfv = GetFileVersion(pvv, cb))
				{
					pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "\tFileVersion: %u.%u.%u.%u\n", 
						HIWORD(pfv->dwFileVersionMS),
						LOWORD(pfv->dwFileVersionMS),
						HIWORD(pfv->dwFileVersionLS),
						LOWORD(pfv->dwFileVersionLS)
						);
				}
			}
		}

		VirtualFree(ImageBase, 0, MEM_RELEASE);
	}
}

void CALLBACK mod_ver(IDebugClient* pDebugClient, PCSTR args)
{
	//if (IsDebuggerPresent()) __debugbreak();

	IDebugControl* pDebugControl;
	IDebugDataSpaces2* pDataSpace;

	if (0 <= pDebugClient->QueryInterface(IID_PPV_ARGS(&pDebugControl)))
	{
		pDebugControl->Output(DEBUG_OUTPUT_ERROR, "\"--%s\"\n", args);

		if (0 <= pDebugClient->QueryInterface(IID_PPV_ARGS(&pDataSpace)))
		{
			PVOID PsLoadedModuleListAddr;

			if (0 <= pDataSpace->ReadDebuggerData(DEBUG_DATA_PsLoadedModuleListAddr, &PsLoadedModuleListAddr, sizeof(PsLoadedModuleListAddr), 0))
			{
				_LDR_DATA_TABLE_ENTRY ldte;

				if (0 <= pDataSpace->ReadVirtual(EXTEND64(PsLoadedModuleListAddr), &ldte.InLoadOrderLinks, sizeof(ldte.InLoadOrderLinks), 0))
				{
					enum { max_modules = 0x200 };
					ULONG m = max_modules;

					if (PWSTR buf = new WCHAR[MINSHORT])
					{
						if (PVOID h = AddVectoredExceptionHandler(TRUE, OnVex))
						{
							while(ldte.InLoadOrderLinks.Flink != PsLoadedModuleListAddr)
							{
								if (!--m)
								{
									break;
								}

								if (0 > pDataSpace->ReadVirtual(
									EXTEND64(CONTAINING_RECORD(ldte.InLoadOrderLinks.Flink, _LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)), 
									&ldte, sizeof(ldte), 0))
								{
									break;
								}

								ldte.FullDllName.Length;
								ULONG rcb;
								if (0 > pDataSpace->ReadVirtual(EXTEND64(ldte.FullDllName.Buffer), buf, ldte.FullDllName.Length, &rcb))
								{
									ldte.FullDllName.Length = 0;
								}
								else
								{
									ldte.FullDllName.Length = (USHORT)rcb;
									ldte.FullDllName.Buffer = buf;
								}

								pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%02x: %p %08x %wZ\n", 
									max_modules - m, ldte.DllBase, ldte.SizeOfImage, &ldte.FullDllName);

								DumpVersion(pDebugControl, pDataSpace, ldte.DllBase, ldte.SizeOfImage);
							}

							RemoveVectoredExceptionHandler(h);
						}

						delete [] buf;
					}
				}
			}

			pDataSpace->Release();
		}

		pDebugControl->Release();
	}
}

_NT_END