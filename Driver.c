#include "ntos.h"
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x15, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x16, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_ID_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x17, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x18, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_FLOAT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)



PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

HANDLE pID;
  
typedef struct _READ
{
	ULONGLONG Address;
	ULONGLONG Response;
	ULONGLONG Size;

} READ, *PREAD;

typedef struct _WRITE
{
	ULONGLONG Address;
	ULONGLONG Value;
	ULONGLONG Size;

} WRITE, *PWRITE;


typedef struct _WRITE_FLOAT
{
	ULONGLONG Address;
	float Value;
	ULONGLONG Size;

} WRITE_FLOAT, *PWRITE_FLOAT;


NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);

NTSTATUS Read(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS Write(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}


NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode == IO_READ_REQUEST)
	{
		PREAD ReadInput = (PREAD)Irp->AssociatedIrp.SystemBuffer;
		PREAD ReadOutput = (PREAD)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;

		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pID, &Process)))
		{
			Read(Process, ReadInput->Address,
				&ReadInput->Response, ReadInput->Size);
		}

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(READ);
	}
	
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		PWRITE WriteInput = (PWRITE)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;

		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pID, &Process)))
		{
			Write(Process, &WriteInput->Value,
				WriteInput->Address, WriteInput->Size);
		}

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(WRITE);
	}
	else if (ControlCode == IO_WRITE_FLOAT)
	{
		PWRITE_FLOAT WriteInput = (PWRITE_FLOAT)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pID, &Process)))
		{
			Write(Process, &WriteInput->Value,
				WriteInput->Address, WriteInput->Size);
		}
;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(WRITE_FLOAT);
	}

	else if (ControlCode == IO_GET_ID_REQUEST)
	{
		PULONG Input = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		pID = *Input;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(Input);
	}

	else if (ControlCode == IO_GET_MODULE_REQUEST)
	{
		PULONGLONG Module = (PULONGLONG)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		PsLookupProcessByProcessId((HANDLE)pID, &Process);

		KeAttachProcess((PKPROCESS)Process); 
		*Module = PsGetProcessSectionBaseAddress(Process);
		KeDetachProcess();

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(Module);
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return Status;
}

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	void *ExceptionTable;
	unsigned int ExceptionTableSize;
	void *GpValue;
	void *NonPagedDebugInfo;
	void *DllBase;
	void *EntryPoint;
	unsigned int SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	unsigned int Flags;
	unsigned __int16 LoadCount;
	unsigned __int16 u1;
	void *SectionPointer;
	unsigned int CheckSum;
	unsigned int CoverageSectionSize;
	void *CoverageSection;
	void *LoadedImports;
	void *Spare;
	unsigned int SizeOfImageNotRounded;
	unsigned int TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	PFILE_OBJECT FileObject;
	PKLDR_DATA_TABLE_ENTRY Entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&Entry->FullDllName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);

	IoCreateFileEx(&FileHandle,
		SYNCHRONIZE | DELETE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL, IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
		NULL);

	ObReferenceObjectByHandle(FileHandle,
		SYNCHRONIZE | DELETE,
		*IoFileObjectType,
		KernelMode,
		&FileObject,
		NULL);

	ObCloseHandle(FileHandle, KernelMode);
	PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
	SectionObjectPointer->ImageSectionObject = NULL;
	MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);
	ObDereferenceObject(FileObject);


	RtlInitUnicodeString(&dev, L"\\Device\\bvowkjfmlksjfm9i2m");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\bvowkjfmlksjfm9i2m");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;


	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

}



NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
