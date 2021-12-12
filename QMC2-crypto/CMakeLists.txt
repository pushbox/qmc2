# CMakeList.txt : CMake project for QMC2-decoder, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

include_directories(
	vendor
	vendor/TarsCpp/util/include
	include
)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

# We don't need all TarsCpp code
set(SOURCE_TEA
	"vendor/TarsCpp/util/src/tc_base64.cpp"
	"vendor/TarsCpp/util/src/tc_tea.cpp"
)

# Add source to this project's executable.
add_library (QMC2-crypto
	${SOURCE_TEA}
	"include/qmc2-crypto/IKeyDec.h"
	"include/qmc2-crypto/StreamCencrypt.h"
	"include/qmc2-crypto/IStreamEncryptAndDecrypt.h"
	"include/qmc2-crypto/KeyDec.h"
	"qmc2-crypto/StreamCencrypt.cpp"
	"qmc2-crypto/KeyDec.cpp")

if (!MSVC)
	target_link_libraries(QMC2-crypto m)
endif()

target_include_directories(QMC2-crypto PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

# TODO: Add tests and install targets if needed.
