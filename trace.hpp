#pragma once

constexpr unsigned int max_unloader_driver = 50;
typedef struct _unloader_information
{
	UNICODE_STRING name;
	PVOID module_start;
	PVOID module_end;
	ULONG64 unload_time;
} unloader_information, * punloader_information;

typedef struct _piddb_cache_entry
{
	LIST_ENTRY list;
	UNICODE_STRING name;
	ULONG stamp;
	NTSTATUS status;
	char _0x0028[16];
}piddb_cache_entry, * ppiddb_cache_entry;

typedef struct _hash_bucket_entry
{
	struct _hash_bucket_entry* next;
	UNICODE_STRING name;
	ULONG hash[5];
} hash_bucket_entry, * phash_bucket_entry;

namespace trace
{
	namespace detail
	{
		inline ERESOURCE& unload_resource()
		{
			static ERESOURCE resource{};
			return resource;
		}

		inline bool& unload_resource_initialized()
		{
			static bool initialized = false;
			return initialized;
		}

		inline NTSTATUS ensure_unload_resource()
		{
			if (!unload_resource_initialized())
			{
				NTSTATUS status = ExInitializeResourceLite(&unload_resource());
				if (!NT_SUCCESS(status))
					return status;
				unload_resource_initialized() = true;
			}

			return STATUS_SUCCESS;
		}

		inline void cleanup_resources()
		{
			if (unload_resource_initialized())
			{
				ExDeleteResourceLite(&unload_resource());
				unload_resource_initialized() = false;
			}
		}

		inline unsigned long long resolve_relative_address(unsigned long long instruction, unsigned long instruction_size, unsigned long offset)
		{
			auto instruction_bytes = reinterpret_cast<unsigned char*>(instruction);
			auto rip_offset = *reinterpret_cast<int*>(instruction_bytes + offset);
			return reinterpret_cast<unsigned long long>(instruction_bytes + instruction_size + rip_offset);
		}

		inline unsigned long long find_piddb_lock(unsigned long long ntoskrnl_address)
		{
			struct pattern_spec { const char* pattern; const char* mask; unsigned long offset; };
			const pattern_spec patterns[] =
			{
				{ "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x", 28 },
				{ "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x", 16 },
				{ "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x", 19 }
			};

			for (const auto& spec : patterns)
			{
				auto address = utils::find_pattern_image(ntoskrnl_address, spec.pattern, spec.mask);
				if (address)
				{
					address += spec.offset;
					return resolve_relative_address(address, 7, 3);
				}
			}

			return 0;
		}

		inline unsigned long long find_piddb_cache_table(unsigned long long ntoskrnl_address)
		{
			struct pattern_spec { const char* pattern; const char* mask; unsigned long offset; };
			const pattern_spec patterns[] =
			{
				{ "\x66\x03\xD2\x48\x8D\x0D", "xxxxxx", 0 },
				{ "\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx", 2 }
			};

			for (const auto& spec : patterns)
			{
				auto address = utils::find_pattern_image(ntoskrnl_address, spec.pattern, spec.mask);
				if (address)
				{
					address += spec.offset;
					return resolve_relative_address(address, 10, 6);
				}
			}

			return 0;
		}
	}

	bool clear_cache(const wchar_t* name, unsigned long stamp)
	{
		bool status = false;

		__try
		{
			unsigned long long ntoskrnl_address = 0;
			unsigned long ntoskrnl_size = 0;
			utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
			DbgPrintEx(0, 0, "[%s] ntoskrnl address 0x%llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);
			if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return status;

			unsigned long long PiDDBLock = detail::find_piddb_lock(ntoskrnl_address);
			if (PiDDBLock == 0) return status;
			DbgPrintEx(0, 0, "[%s] PiDDBLock address 0x%llx\n", __FUNCTION__, PiDDBLock);

			unsigned long long PiDDBCacheTable = detail::find_piddb_cache_table(ntoskrnl_address);
			if (PiDDBCacheTable == 0) return status;
			DbgPrintEx(0, 0, "[%s] PiDDBCacheTable address 0x%llx \n", __FUNCTION__, PiDDBCacheTable);

			piddb_cache_entry in_entry{};
			in_entry.stamp = stamp;
			RtlInitUnicodeString(&in_entry.name, name);

			if (ExAcquireResourceExclusiveLite((PERESOURCE)PiDDBLock, TRUE))
			{
				__try
				{
					ppiddb_cache_entry ret_entry = (ppiddb_cache_entry)RtlLookupElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, &in_entry);
					if (ret_entry)
					{
						DbgPrintEx(0, 0, "[%s] found %ws driver cache 0x%p \n", __FUNCTION__, ret_entry->name.Buffer, ret_entry->status);

						PLIST_ENTRY prev = ret_entry->list.Blink;
						PLIST_ENTRY next = ret_entry->list.Flink;
						if (prev && next)
						{
							prev->Flink = next;
							next->Blink = prev;
						}

						if (RtlDeleteElementGenericTableAvl((PRTL_AVL_TABLE)PiDDBCacheTable, ret_entry))
						{
							PRTL_AVL_TABLE avl = ((PRTL_AVL_TABLE)PiDDBCacheTable);
							if (avl->DeleteCount > 0) avl->DeleteCount--;

							status = true;
						}
					}
				}
				__finally
				{
					ExReleaseResourceLite((PERESOURCE)PiDDBLock);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "[%s] exception 0x%X\n", __FUNCTION__, GetExceptionCode());
		}

		return status;
	}

	bool clear_cache_by_name(const wchar_t* name)
	{
		bool status = false;

		__try
		{
			unsigned long long ntoskrnl_address = 0;
			unsigned long ntoskrnl_size = 0;
			utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
			DbgPrintEx(0, 0, "[%s] ntoskrnl address 0x%llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);
			if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return status;

			unsigned long long PiDDBLock = detail::find_piddb_lock(ntoskrnl_address);
			if (PiDDBLock == 0) return status;
			DbgPrintEx(0, 0, "[%s] PiDDBLock address 0x%llx\n", __FUNCTION__, PiDDBLock);

			unsigned long long PiDDBCacheTable = detail::find_piddb_cache_table(ntoskrnl_address);
			if (PiDDBCacheTable == 0) return status;
			DbgPrintEx(0, 0, "[%s] PiDDBCacheTable address 0x%llx \n", __FUNCTION__, PiDDBCacheTable);

			if (ExAcquireResourceExclusiveLite((PERESOURCE)PiDDBLock, TRUE))
			{
				__try
				{
					PRTL_AVL_TABLE table = (PRTL_AVL_TABLE)PiDDBCacheTable;
					BOOLEAN restart = TRUE;
					ppiddb_cache_entry entry = (ppiddb_cache_entry)RtlEnumerateGenericTableAvl(table, restart);
					restart = FALSE;
					while (entry)
					{
						if (entry->name.Buffer && wcsstr(entry->name.Buffer, name))
						{
							unsigned long stamp = entry->stamp;
							return clear_cache(name, stamp);
						}

						entry = (ppiddb_cache_entry)RtlEnumerateGenericTableAvl(table, restart);
					}
				}
				__finally
				{
					ExReleaseResourceLite((PERESOURCE)PiDDBLock);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "[%s] exception 0x%X\n", __FUNCTION__, GetExceptionCode());
		}

		return status;
	}

	bool clear_unloaded_driver(const wchar_t* name)
	{
		bool status = false;

		__try
		{
			unsigned long long ntoskrnl_address = 0;
			unsigned long ntoskrnl_size = 0;
			utils::get_module_base_address("ntoskrnl.exe", ntoskrnl_address, ntoskrnl_size);
			DbgPrintEx(0, 0, "[%s] ntoskrnl address 0x%llx, size %ld\n", __FUNCTION__, ntoskrnl_address, ntoskrnl_size);
			if (ntoskrnl_address == 0 || ntoskrnl_size == 0) return status;

			unsigned long long MmUnloadedDrivers = utils::find_pattern_image(ntoskrnl_address,
				"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
				"xxx????xxx");
			if (MmUnloadedDrivers == 0) return status;
			MmUnloadedDrivers = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmUnloadedDrivers) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmUnloadedDrivers) + 3));
			DbgPrintEx(0, 0, "[%s] MmUnloadedDrivers pointer location 0x%llx\n", __FUNCTION__, MmUnloadedDrivers);
			if (!MmIsAddressValid(reinterpret_cast<PVOID>(MmUnloadedDrivers)))
				return status;

			unsigned long long MmLastUnloadedDriver = utils::find_pattern_image(ntoskrnl_address,
				"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
				"xx????xxx");
			if (MmLastUnloadedDriver == 0) return status;
			MmLastUnloadedDriver = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 6 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 2));
			DbgPrintEx(0, 0, "[%s] MmLastUnloadedDriver pointer location 0x%llx \n", __FUNCTION__, MmLastUnloadedDriver);
			if (!MmIsAddressValid(reinterpret_cast<PVOID>(MmLastUnloadedDriver)))
				return status;

			punloader_information* unloaders_pointer = reinterpret_cast<punloader_information*>(MmUnloadedDrivers);
			if (!MmIsAddressValid(unloaders_pointer))
				return status;
			punloader_information unloaders = *unloaders_pointer;
			if (!MmIsAddressValid(unloaders))
				return status;

			unsigned long* unloaders_count = reinterpret_cast<unsigned long*>(MmLastUnloadedDriver);
			if (!MmIsAddressValid(unloaders_count))
				return status;

			DbgPrintEx(0, 0, "[%s] MmUnloadedDrivers value 0x%llx, count_ptr 0x%llx\n",
				__FUNCTION__, unloaders, unloaders_count);

			if (!NT_SUCCESS(detail::ensure_unload_resource()))
				return status;

			if (ExAcquireResourceExclusiveLite(&detail::unload_resource(), TRUE))
			{
				__try
				{
					unsigned long count = *unloaders_count;
					if (count > max_unloader_driver)
						count = max_unloader_driver;

					for (unsigned long i = 0; i < count; i++)
					{
						if (!MmIsAddressValid(&unloaders[i]))
							continue;

						unloader_information& t = unloaders[i];
						const wchar_t* sys = t.name.Buffer;

						if (!sys || !MmIsAddressValid((PVOID)sys))
							continue;

						DbgPrintEx(0, 0, "[%s] %.2d %ws \n", __FUNCTION__, i, sys);
						if (wcsstr(sys, name))
						{
							DbgPrintEx(0, 0, "[%s] found unloader %ws driver \n", __FUNCTION__, t.name.Buffer);

							t.module_start = (void*)((unsigned long long)t.module_start + 0x1234);
							t.module_end = (void*)((unsigned long long)t.module_end - 0x123);
							t.unload_time += 0x20;
							utils::random_wstring(t.name.Buffer, t.name.Length / 2 - 4);

							DbgPrintEx(0, 0, "[%s] random string is %ws \n", __FUNCTION__, t.name.Buffer);
							status = true;
						}
					}
				}
				__finally
				{
					ExReleaseResourceLite(&detail::unload_resource());
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "[%s] exception 0x%X\n", __FUNCTION__, GetExceptionCode());
		}

		return status;
	}

	bool clear_hash_bucket_list(const wchar_t* name)
	{
		bool status = false;

		__try
		{
			unsigned long long ci_address = 0;
			unsigned long ci_size = 0;
			utils::get_module_base_address("CI.dll", ci_address, ci_size);
			DbgPrintEx(0, 0, "[%s] ci address 0x%llx, size %ld\n", __FUNCTION__, ci_address, ci_size);
			if (ci_address == 0 || ci_size == 0) return status;

			unsigned long long KernelHashBucketList = utils::find_pattern_image(ci_address,
				"\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00",
				"xxx????x?xxxxxxx");
			if (KernelHashBucketList == 0) return status;
			KernelHashBucketList = detail::resolve_relative_address(KernelHashBucketList, 7, 3);
			DbgPrintEx(0, 0, "[%s] g_KernelHashBucketList address 0x%llx\n", __FUNCTION__, KernelHashBucketList);

			unsigned long long HashCacheLock = utils::find_pattern_image(ci_address,
				"\x48\x8D\x0D\x00\x00\x00\x00\x48\xFF\x15\x00\x00\x00\x00\x0F\x1F\x44\x00\x00\x48\x8B\x1D\x00\x00\x00\x00\xEB",
				"xxx????xxx????xxxx?xxx????x");
			if (HashCacheLock == 0) return status;
			HashCacheLock = detail::resolve_relative_address(HashCacheLock, 7, 3);
			DbgPrintEx(0, 0, "[%s] g_HashCacheLock address 0x%llx\n", __FUNCTION__, HashCacheLock);

			if (ExAcquireResourceExclusiveLite((PERESOURCE)HashCacheLock, TRUE))
			{
				__try
				{
					phash_bucket_entry current_entry = ((phash_bucket_entry)KernelHashBucketList)->next;
					phash_bucket_entry prev_entry = (phash_bucket_entry)KernelHashBucketList;

					while (current_entry)
					{
						if (!current_entry->name.Buffer)
						{
							prev_entry = current_entry;
							current_entry = current_entry->next;
							continue;
						}

						DbgPrintEx(0, 0, "[%s] %ws 0x%x\n", __FUNCTION__, current_entry->name.Buffer, current_entry->hash[0]);

						if (wcsstr(current_entry->name.Buffer, name))
						{
							DbgPrintEx(0, 0, "[%s] found %ws driver \n", __FUNCTION__, current_entry->name.Buffer);

							prev_entry->next = current_entry->next;

							current_entry->hash[0] = current_entry->hash[1] = 1;
							current_entry->hash[2] = current_entry->hash[3] = 1;
							utils::random_wstring(current_entry->name.Buffer, current_entry->name.Length / 2 - 4);

							ExFreePoolWithTag(current_entry, 0);
							status = true;
							break;
						}
						else
						{
							prev_entry = current_entry;
							current_entry = current_entry->next;
						}
					}
				}
				__finally
				{
					ExReleaseResourceLite((PERESOURCE)HashCacheLock);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "[%s] exception 0x%X\n", __FUNCTION__, GetExceptionCode());
		}

		return status;
	}

	bool clear_ci_ea_cache_lookaside_list()
	{
		bool status = false;

		__try
		{
			unsigned long long ci_address = 0;
			unsigned long ci_size = 0;
			utils::get_module_base_address("CI.dll", ci_address, ci_size);
			DbgPrintEx(0, 0, "[%s] ci address 0x%llx, size %ld\n", __FUNCTION__, ci_address, ci_size);
			if (ci_address == 0 || ci_size == 0) return status;

			unsigned long long CiEaCacheLookasideList = utils::find_pattern_image(ci_address,
				"\x8B\x15\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x44\x8B\x05\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\xFF\x05\x00\x00\x00\x00\xFF\x15",
				"xx????xxx????xxx????xx????xx????xx");
			if (CiEaCacheLookasideList == 0) return status;
			CiEaCacheLookasideList -= 0x1B;
			CiEaCacheLookasideList = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 3));
			DbgPrintEx(0, 0, "[%s] g_CiEaCacheLookasideList address 0x%llx\n", __FUNCTION__, CiEaCacheLookasideList);

			PLOOKASIDE_LIST_EX g_CiEaCacheLookasideList = (PLOOKASIDE_LIST_EX)CiEaCacheLookasideList;
			ULONG size = g_CiEaCacheLookasideList->L.Size;
			ExDeleteLookasideListEx(g_CiEaCacheLookasideList);
			if (NT_SUCCESS(ExInitializeLookasideListEx(g_CiEaCacheLookasideList, NULL, NULL, PagedPool, 0, size, 'csIC', 0)))
			{
				DbgPrintEx(0, 0, "[%s] clear g_CiEaCacheLookasideList \n", __FUNCTION__);
				status = true;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrintEx(0, 0, "[%s] exception 0x%X\n", __FUNCTION__, GetExceptionCode());
		}

		return status;
	}

	inline void cleanup()
	{
		detail::cleanup_resources();
	}
}
