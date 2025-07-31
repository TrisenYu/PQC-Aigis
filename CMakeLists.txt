# SPDX-LICENSE-IDENTIFIER: GPL2.0
#
# (C) All rights reserved. Author: <kisfg@hotmail.com> in 2025
# Created at 2025年07月31日 星期四 15时26分35秒
# Last modified at 2025年07月31日 星期四 22时05分51秒
cmake_minimum_required(VERSION 3.13.0)
project(aigis C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)


message(STATUS "c compiler: ${CMAKE_C_COMPILER}")
if (DEFINED AIGIS_PARAM_CONF)
	message(STATUS "param_conf: ${AIGIS_PARAM_CONF}")
	add_compile_definitions(-DAIGIS_PARAM_CONF=${AIGIS_PARAM_CONF})
else()
	add_compile_definitions(-DAIGIS_PARAM_CONF=1)
endif()
if (DEFINED AIGIS_KDF_CONF)
	message(STATUS "kdf_conf: ${AIGIS_KDF_CONF}")
	add_compile_definitions(-DAIGIS_KDF_CONF=${AIGIS_KDF_CONF})
else()
	add_compile_definitions(-DAIGIS_KDF_CONF=1)
endif()


include_directories(include .)
file(GLOB_RECURSE src_files "src/*.c")
# 编译为静态链接库
add_library(aigis STATIC ${src_files})

file(GLOB test_enc_files "test/enc/*.c")
file(GLOB test_sig_files "test/sig/*.c")
set(test_cases ${test_enc_files} ${test_sig_files})
set(testcases "")
foreach(test_case ${test_cases})
	get_filename_component(test_name ${test_case} NAME_WE)
	add_executable(${test_name} ${test_case})
	target_link_libraries(${test_name} aigis)
	add_test(
		NAME ${test_name}
		COMMAND ./${test_name}
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
	)
	list(APPEND testcases ${test_name})
endforeach()

add_custom_target(
	run
	DEPENDS ${testcases}
	COMMENT "test testcases"
)

foreach(t ${testcases})
	add_custom_command(
        TARGET run
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Running ${t}..."
        COMMAND $<TARGET_FILE:${t}>
        COMMAND ${CMAKE_COMMAND} -E echo ""  # 测试间空行分隔
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endforeach()
