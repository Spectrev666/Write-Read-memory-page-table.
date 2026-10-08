#pragma once
#include <ntddk.h>

#define LOG_DRIVER(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __VA_ARGS__)

using u64 = UINT64;
using u16 = UINT16;
using u32 = UINT32;

namespace drv
{
  namespace memory
  {
    template <typename T>
    [[nodiscard]] inline T read_physical(u64 phys_addr)
    {
      T value{};
      SIZE_T bytesC = 0;
      MM_COPY_ADDRESS mm_copy_addr = {};
      mm_copy_addr.PhysicalAddress.QuadPart = phys_addr;

      __try
      {
        NTSTATUS copy_memory = MmCopyMemory(&value, mm_copy_addr, sizeof(T), MM_COPY_MEMORY_PHYSICAL, &bytesC);
        if (!NT_SUCCESS(copy_memory) || bytesC != sizeof(T))
          return {};
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        return {};
      }

      return value;
    }

    template <typename T>
    [[nodiscard]] inline T* mmap_physical(u64 phys_addr, u64 size)
    {
      PHYSICAL_ADDRESS addr;
      addr.QuadPart = phys_addr;

      return reinterpret_cast<T*>(MmMapIoSpace(addr, size, MmCached));
    }
    [[nodiscard]] NTSTATUS WPM(ULONG PID, u64 VirtualAddress, u64 SIZE, u64 buffer);
    [[nodiscard]] NTSTATUS RPM(ULONG PID, u64 VirtualAddress, u64 SIZE, u64 buffer);
    [[nodiscard]] u64 translate_virtual_to_physical(u64 DTB, u64 addr);
  }

  namespace communication
  {
    [[nodiscard]] NTSTATUS send_message_to_usermode(u64 buffer, u64 size);
  }
}

extern "C"
{
  NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
}
typedef u64(*PsGetProcessDirectoryTableBase_t)(PEPROCESS Process);
