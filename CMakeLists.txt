cmake_minimum_required(VERSION 3.13)
project(omnidns C)

option(HOST_TESTS "Build unit tests (host)" OFF)
option(SANITIZE "Build with ASan/UBSan" OFF)
option(FUZZ "Build libFuzzer targets (clang)" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wshadow -Wformat=2
	-Wstrict-prototypes -Wmissing-prototypes -Wno-missing-field-initializers
	-D_GNU_SOURCE)

if(SANITIZE)
	add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
	add_link_options(-fsanitize=address,undefined)
endif()

find_path(UBOX_INCLUDE libubox/uloop.h)
find_library(UBOX_LIB NAMES ubox)
find_library(UCI_LIB NAMES uci)
find_library(MNL_LIB NAMES mnl)
find_library(NFTNL_LIB NAMES nftnl)
include_directories(${UBOX_INCLUDE} src)

file(GLOB_RECURSE CORE_SRC CONFIGURE_DEPENDS src/*.c)
list(FILTER CORE_SRC EXCLUDE REGEX ".*/src/main\\.c$")

add_library(omnicore STATIC ${CORE_SRC})
target_link_libraries(omnicore ${UBOX_LIB} ${UCI_LIB} ${NFTNL_LIB} ${MNL_LIB})

if(EXISTS ${CMAKE_SOURCE_DIR}/src/main.c)
	add_executable(omnidns src/main.c)
	target_link_libraries(omnidns omnicore)
	install(TARGETS omnidns RUNTIME DESTINATION sbin)
endif()

if(HOST_TESTS)
	enable_testing()
	file(GLOB UNIT_TESTS CONFIGURE_DEPENDS tests/unit/test_*.c)
	foreach(t ${UNIT_TESTS})
		get_filename_component(name ${t} NAME_WE)
		add_executable(${name} ${t})
		target_link_libraries(${name} omnicore)
		add_test(NAME ${name} COMMAND ${name} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/unit)
		# the SDK ctest wrapper preloads runas.so, which breaks ASan
		set_tests_properties(${name} PROPERTIES SKIP_RETURN_CODE 77
			ENVIRONMENT "LD_PRELOAD=")
	endforeach()
	# Tests needing an unprivileged netns (nftables) are wrapped by the test
	# itself re-exec'ing under `unshare -rn` (see tests/unit/test.h).
endif()

if(FUZZ)
	file(GLOB FUZZERS CONFIGURE_DEPENDS tests/fuzz/fuzz_*.c)
	foreach(f ${FUZZERS})
		get_filename_component(name ${f} NAME_WE)
		add_executable(${name} ${f})
		target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
		target_link_options(${name} PRIVATE -fsanitize=fuzzer)
		target_link_libraries(${name} omnicore)
	endforeach()
endif()
