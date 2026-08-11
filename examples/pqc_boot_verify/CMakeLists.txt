# SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.22)


include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(PQC_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}")
get_filename_component(PQC_REPO_ROOT "${PQC_REPO_ROOT}" ABSOLUTE)
idf_build_set_property(EXTRA_CMAKE_ARGS "-DPROJECT_SOURCE_DIR=${PQC_REPO_ROOT}" APPEND)

get_filename_component(ESP_PQC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
idf_build_set_property(BOOTLOADER_EXTRA_COMPONENT_DIRS "${ESP_PQC_ROOT}" APPEND)

idf_build_set_property(EXTRA_CMAKE_ARGS
    "-DPQC_BOOTLOADER_SUPPORT_INCLUDE=${PQC_REPO_ROOT}/bootloader_components/bootloader_support/include"
    APPEND)

project(pqc_boot_verify)

set(CUSTOM_MEMORY_LD_IN "${CMAKE_CURRENT_LIST_DIR}/bootloader_components/main/ld/${IDF_TARGET}/memory.ld.in")
set(CUSTOM_MEMORY_LD_OUT "${CMAKE_BINARY_DIR}/ld/memory.ld")
message(STATUS "PQC: Using custom memory.ld.in from ${CUSTOM_MEMORY_LD_IN}")

idf_build_get_property(sdkconfig_header SDKCONFIG_HEADER)
idf_build_get_property(config_dir CONFIG_DIR)
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/ld")

add_custom_command(
    OUTPUT "${CUSTOM_MEMORY_LD_OUT}"
    COMMAND ${CMAKE_COMMAND}
        "-DCC=${CMAKE_C_COMPILER}"
        "-DSOURCE=${CUSTOM_MEMORY_LD_IN}"
        "-DTARGET=${CUSTOM_MEMORY_LD_OUT}"
        "-DCFLAGS=-I\"${config_dir}\" -I\"${CMAKE_CURRENT_LIST_DIR}/bootloader_components/main/ld\" -I\"${IDF_PATH}/components/esp_system/ld\" -I\"${IDF_PATH}/components/esp_system/ld/${IDF_TARGET}\""
        -P "${IDF_PATH}/tools/cmake/linker_script_preprocessor.cmake"
    MAIN_DEPENDENCY "${CUSTOM_MEMORY_LD_IN}"
    DEPENDS "${sdkconfig_header}"
    COMMENT "PQC: Preprocessing custom memory.ld.in -> memory.ld"
    VERBATIM)

add_custom_target(pqc_memory_ld_preprocess DEPENDS "${CUSTOM_MEMORY_LD_OUT}")
add_dependencies(__idf_esp_system pqc_memory_ld_preprocess)

target_link_directories(__idf_esp_system BEFORE INTERFACE "${CMAKE_BINARY_DIR}/ld")

idf_build_get_property(build_dir BUILD_DIR)
idf_build_get_property(project_bin PROJECT_BIN)

set(PQC_SIGN_TOOL "${CMAKE_CURRENT_LIST_DIR}/scripts/pqc_sign.py")
set(PQC_SK "${CMAKE_CURRENT_LIST_DIR}/keys/pqc_ml_dsa_65_secret.bin")
set(PQC_PK "${CMAKE_CURRENT_LIST_DIR}/keys/pqc_ml_dsa_65_public.bin")
set(SIGNING_KEY "${CMAKE_CURRENT_LIST_DIR}/${CONFIG_SECURE_BOOT_SIGNING_KEY}")
set(APP_BIN "${build_dir}/${project_bin}")

add_custom_target(pqc_sign ALL
    COMMAND ${PYTHON} "${PQC_SIGN_TOOL}" sign
        "${APP_BIN}"
        --signing-key "${SIGNING_KEY}"
        --pqc-key "${PQC_SK}"
        --pqc-pk "${PQC_PK}"
    COMMENT "PQC: Appending ML-DSA-65 signature block to ${project_bin}"
    VERBATIM
)
add_dependencies(pqc_sign gen_project_binary)
