#include <ntddk.h>
#include <intrin.h>

#include "prototype.h"
#include "shared.h"

extern "C" int _fltused = 0;
HANDLE g_section_handle = nullptr;

namespace
{
  enum class EPROCESSOF : u32
  {
    DTB = 0x28 
  };

  namespace Paging
  {
    constexpr u64 AddressMask = 0x00FFFFFFFFFFF000ULL;

    constexpr u64 PageSize2MBMask = 0x00FFFFFFFFE00000ULL;
    constexpr u64 Offset2MBMask = 0x1FFFFFULL;

    constexpr u64 PageSize1GBMask = 0x000FFFFFC0000000ULL;
    constexpr u64 Offset1GBMask = 0x000000003FFFFFFFULL;

    constexpr u64 Offset4KBMask = 0xFFFULL;
    constexpr u64 EntryPresentBit = 0x1;
    constexpr u64 LargePageBit = 0x80;
    enum Shift : u32 { PML4 = 39, PDPT = 30, PD = 21, PT = 12 };
    constexpr u64 IndexMask = 0x1FF;
  }

  inline bool la57_supported()
  {
    u64 cr4 = __readcr4();
    return (cr4 & (1ULL << 12)) != 0;
  }
}

[[nodiscard]] u64 drv::memory::translate_virtual_to_physical(u64 DTB, u64 addr)
{
  using namespace Paging;

  u64 pml4_table_base = DTB;

  if (la57_supported())
  {
    u16 pml5 = (u16)((addr >> 48) & IndexMask);
    u64 pml5_target = DTB + ((u64)pml5 * sizeof(u64));
    u64 pml5e = drv::memory::read_physical<u64>(pml5_target);

    if ((pml5e & EntryPresentBit) == 0) return 0;

    pml4_table_base = pml5e & AddressMask;
  }

  u16 pml4 = (u16)((addr >> PML4) & IndexMask);
  u16 pdpt = (u16)((addr >> PDPT) & IndexMask);
  u16 pd = (u16)((addr >> PD) & IndexMask);
  u16 pt = (u16)((addr >> PT) & IndexMask);

  u64 pml4_target = pml4_table_base + ((u64)pml4 * sizeof(u64));
  u64 pml4e = drv::memory::read_physical<u64>(pml4_target);

  if ((pml4e & EntryPresentBit) == 0) return 0;

  u64 pdpt_table_base = pml4e & AddressMask;
  u64 pdpt_target = pdpt_table_base + ((u64)pdpt * sizeof(u64));
  u64 pdpte = drv::memory::read_physical<u64>(pdpt_target);

  if ((pdpte & EntryPresentBit) == 0) return 0;

  if (pdpte & LargePageBit)
  {
    u64 physical_page_1gb = pdpte & PageSize1GBMask;
    u64 offset_1gb = addr & Offset1GBMask;
    return physical_page_1gb + offset_1gb;
  }

  u64 pd_table_base = pdpte & AddressMask;
  u64 pd_target = pd_table_base + ((u64)pd * sizeof(u64));
  u64 pde = drv::memory::read_physical<u64>(pd_target);

  if ((pde & EntryPresentBit) == 0) return 0;

  if (pde & LargePageBit)
  {
    u64 physical_page_2mb = pde & PageSize2MBMask;
    u64 offset_2mb = addr & Offset2MBMask;
    return physical_page_2mb + offset_2mb;
  }

  u64 pt_table_base = pde & AddressMask;
  u64 pt_target = pt_table_base + ((u64)pt * sizeof(u64));
  u64 pte = drv::memory::read_physical<u64>(pt_target);

  if ((pte & EntryPresentBit) == 0) return 0;

  u64 physical_page_4kb = pte & AddressMask;
  u64 offset_4kb = addr & Offset4KBMask;

  return physical_page_4kb + offset_4kb;
}

static u64 GetProcessCR3(ULONG PID)
{
  using namespace Paging;

  PEPROCESS target_process = nullptr;
  NTSTATUS eprocess = PsLookupProcessByProcessId((HANDLE)PID, &target_process);

  if (!NT_SUCCESS(eprocess))
    return 0;

  u64 cr3_value = 0;

  __try
  {
    u64* p_cr3 = reinterpret_cast<u64*>(reinterpret_cast<char*>(target_process) + static_cast<u32>(EPROCESSOF::DTB));
    cr3_value = *p_cr3;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    LOG_DRIVER("error dtb cr3 finded");
    cr3_value = 0;
  }
  ObDereferenceObject(target_process);

  return cr3_value & AddressMask;
}

[[nodiscard]] NTSTATUS drv::memory::WPM(ULONG PID, u64 VirtualAddress, u64 SIZE, u64 buffer)
    {
    if (PID == NULL)
      return STATUS_UNSUCCESSFUL;

    u64 CR3 = GetProcessCR3(PID);

    if (CR3 == 0)
      return STATUS_NOT_FOUND;

    LOG_DRIVER("pid process: %lu, virtualaddress: 0x%llx, size: %llu, cr3 addr: 0x%llx\n", PID, VirtualAddress, SIZE, CR3);
    u64 current_virtual = VirtualAddress;
    u64 nice_buffer = buffer;
    u64 bytes_remaining = SIZE;

    while (bytes_remaining > 0)
    {
      u64 page_offset = current_virtual & 0xFFF;
      u64 bytes_to_page_end = 4096 - page_offset;
      u64 chunk_size = (bytes_remaining < bytes_to_page_end) ? bytes_remaining : bytes_to_page_end;
      u64 PhysicalAddr = translate_virtual_to_physical(CR3, current_virtual);

      if (PhysicalAddr == 0)
      {
        LOG_DRIVER("write process memory failed. to translate virtual address 0x%llx\n", current_virtual);
        return STATUS_INVALID_ADDRESS;
      }
      void* mmap_mem = drv::memory::mmap_physical<void>(PhysicalAddr, chunk_size);

      if (mmap_mem == nullptr)
      {
        LOG_DRIVER("write process memory failed. to map physical memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
      }

      __try
      {
        RtlCopyMemory(mmap_mem, reinterpret_cast<void*>(nice_buffer), chunk_size);
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        LOG_DRIVER("write process memory failed. intercepted during write operation\n");
        MmUnmapIoSpace(mmap_mem, chunk_size);
        return STATUS_UNHANDLED_EXCEPTION;
      }
      MmUnmapIoSpace(mmap_mem, chunk_size);

      current_virtual += chunk_size;
      nice_buffer += chunk_size;
      bytes_remaining -= chunk_size;
    }
    return STATUS_SUCCESS;
  }

[[nodiscard]] NTSTATUS drv::memory::RPM(ULONG PID, u64 VirtualAddress, u64 SIZE, u64 buffer)
  {
      
    if (PID == NULL)
      return STATUS_UNSUCCESSFUL;


    u64 CR3 = GetProcessCR3(PID);

    if (CR3 == 0)
      return STATUS_NOT_FOUND;

    u64 current_virtual = VirtualAddress;
    u64 nice_buffer = buffer;
    u64 bytes_remaining = SIZE;

    while (bytes_remaining > 0)
    {
      u64 page_offset = current_virtual & 0xFFF;
      u64 bytes_to_page_end = 4096 - page_offset;
      u64 chunk_size = (bytes_remaining < bytes_to_page_end) ? bytes_remaining : bytes_to_page_end;
      u64 PhysicalAddr = translate_virtual_to_physical(CR3, current_virtual);

      if (PhysicalAddr == 0)
      {
        LOG_DRIVER("read process memory failed. to translate virtual address 0x%llx\n", current_virtual);
        return STATUS_INVALID_ADDRESS;
      }
      void* mmap_mem = drv::memory::mmap_physical<void>(PhysicalAddr, chunk_size);

      if (mmap_mem == nullptr)
      {
        LOG_DRIVER("read process memory failed. to map physical memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
      }

      __try
      {
        RtlCopyMemory(reinterpret_cast<void*>(nice_buffer), mmap_mem, chunk_size);
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
        LOG_DRIVER("read process memory failed. intercepted during write operation\n");
        MmUnmapIoSpace(mmap_mem, chunk_size);
        return STATUS_UNHANDLED_EXCEPTION;
      }
      MmUnmapIoSpace(mmap_mem, chunk_size);

      current_virtual += chunk_size;
      nice_buffer += chunk_size;
      bytes_remaining -= chunk_size;
    }
    return STATUS_SUCCESS;
  }

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
  UNREFERENCED_PARAMETER(DriverObject);
  LOG_DRIVER("driver unloaded successfully.\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  UNREFERENCED_PARAMETER(RegistryPath);

  LOG_DRIVER("Driver loaded. Initializing async process monitor...\n");
  DriverObject->DriverUnload = DriverUnload;

  // ...
  
  return STATUS_SUCCESS;
}
