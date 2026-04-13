cmake_minimum_required(VERSION 3.10)
project(lsplt)

find_program(CCACHE ccache)

if (CCACHE)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
endif ()

if (LSPLT_STANDALONE)
    find_package(cxx REQUIRED CONFIG)
    link_libraries(cxx::cxx)
endif()

add_definitions(-std=c++20)

set(SOURCES lsplt.cc elf_util.cc)

option(LSPLT_BUILD_SHARED "If ON, lsplt will also build shared library" ON)

if (LSPLT_BUILD_SHARED)
    message(STATUS "Building lsplt as a shared library")
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_include_directories(${PROJECT_NAME} PUBLIC include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(${PROJECT_NAME} PRIVATE -flto -Oz -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections
    			  -fno-use-cxa-atexit -fno-threadsafe-statics -fno-unroll-loops -fno-jump-tables -fno-c++-static-destructors
    			  -fno-keep-static-consts -fno-keep-persistent-storage-variables -fno-register-global-dtors-with-atexit
    			  -fwhole-program-vtables -fno-common -fno-verbose-asm -fvirtual-function-elimination -fno-rtti -fno-exceptions
    			  -fno-stack-protector -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-ident -fmerge-all-constants)
    target_link_options(${PROJECT_NAME} PRIVATE -flto -unwindlib=none -Wl,-s -Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,--no-rosegment
    			-Wl,--strip-all -Wl,-z,norelro -Wl,--build-id=none -Wl,--icf=all -Wl,--as-needed -Wl,-Bsymbolic -Wl,--no-eh-frame-hdr)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:${PROJECT_NAME}>
            ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}/${PROJECT_NAME}
            COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:${PROJECT_NAME}>)

    target_link_libraries(${PROJECT_NAME} PUBLIC log)
endif()

add_library(${PROJECT_NAME}_static STATIC ${SOURCES})
target_include_directories(${PROJECT_NAME}_static PUBLIC include)
target_include_directories(${PROJECT_NAME}_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(${PROJECT_NAME}_static PRIVATE -flto -Oz -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections
    			  -fno-use-cxa-atexit -fno-threadsafe-statics -fno-unroll-loops -fno-jump-tables -fno-c++-static-destructors
    			  -fno-keep-static-consts -fno-keep-persistent-storage-variables -fno-register-global-dtors-with-atexit
    			  -fwhole-program-vtables -fno-common -fno-verbose-asm -fvirtual-function-elimination -fno-rtti -fno-exceptions
    			  -fno-stack-protector -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-ident -fmerge-all-constants)
target_link_options(${PROJECT_NAME}_static PRIVATE -flto -unwindlib=none -Wl,-s -Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,--no-rosegment
    			-Wl,--strip-all -Wl,-z,norelro -Wl,--build-id=none -Wl,--icf=all -Wl,--as-needed -Wl,-Bsymbolic -Wl,--no-eh-frame-hdr)

if (NOT DEFINED DEBUG_SYMBOLS_PATH)
    set(DEBUG_SYMBOLS_PATH ${CMAKE_BINARY_DIR}/symbols)
endif()

target_link_libraries(${PROJECT_NAME}_static PUBLIC log)
