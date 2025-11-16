#pragma once

#include <ntifs.h>
#include "common.hpp"

namespace loader
{
	using ::KYADRV_MAP_REQUEST;
	using ::PKYADRV_MAP_REQUEST;
	using ::KYADRV_MAP_RESULT;
	using ::PKYADRV_MAP_RESULT;
NTSTATUS initialize();
void cleanup();
NTSTATUS map_image_from_request(const KYADRV_MAP_REQUEST* request, SIZE_T requestBufferSize, KYADRV_MAP_RESULT* result);
}
