cmake_minimum_required(VERSION 3.22)
project(totk_android_loader_probe LANGUAGES C CXX ASM)

if(NOT ANDROID)
  message(FATAL_ERROR "This experiment must be cross-compiled with the Android NDK toolchain")
endif()
if(NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  message(FATAL_ERROR "This experiment requires arm64-v8a, got ${CMAKE_ANDROID_ARCH_ABI}")
endif()

add_executable(loader_probe
    src/loader_probe.cpp
    src/module_image.cpp
    src/guest_window.cpp
    src/vm_query.cpp
    src/signal_context.cpp
    src/guest_thread_context.cpp
    src/guest_stack_probe.S
    src/private_elf.cpp
    src/private_module_mapping.cpp
    src/relocation_stream.cpp
    src/guest_startup_plan.cpp
    src/entry_binding_consumption.cpp
    src/entry_binding_reader.cpp
    src/vulkan_probe.cpp
)
target_compile_features(loader_probe PRIVATE cxx_std_20)
target_compile_definitions(loader_probe PRIVATE VK_USE_PLATFORM_ANDROID_KHR)
target_compile_options(loader_probe PRIVATE -Wall -Wextra -Wpedantic -Werror -fexceptions -frtti -ffixed-x18)
target_link_options(loader_probe PRIVATE "-Wl,-z,max-page-size=16384" "-Wl,-z,common-page-size=4096")
target_link_libraries(loader_probe PRIVATE log atomic vulkan)

set(NATIVE_APP_GLUE "${ANDROID_NDK}/sources/android/native_app_glue")
add_library(loader_probe_app SHARED
    src/loader_probe.cpp
    src/module_image.cpp
    src/guest_window.cpp
    src/vm_query.cpp
    src/signal_context.cpp
    src/guest_thread_context.cpp
    src/guest_stack_probe.S
    src/private_elf.cpp
    src/private_module_mapping.cpp
    src/relocation_stream.cpp
    src/guest_startup_plan.cpp
    src/entry_binding_consumption.cpp
    src/entry_binding_reader.cpp
    src/vulkan_probe.cpp
    src/native_activity.cpp
    "${NATIVE_APP_GLUE}/android_native_app_glue.c"
)
target_compile_definitions(loader_probe_app PRIVATE LOADER_PROBE_LIBRARY=1 VK_USE_PLATFORM_ANDROID_KHR)
target_include_directories(loader_probe_app PRIVATE "${NATIVE_APP_GLUE}")
target_compile_options(loader_probe_app PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror;-fexceptions;-frtti;-ffixed-x18>
)
target_link_options(loader_probe_app PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=4096"
)
target_link_libraries(loader_probe_app PRIVATE android log atomic vulkan)
