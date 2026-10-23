#pragma once

#include <cstddef>
#include "vulkan_probe.h"
int run_loader_probe(const char* const* private_module_paths = nullptr,
                     size_t private_module_path_count = 0,
                     const char* private_relocation_stream_path = nullptr,
                     const char* private_entry_binding_path = nullptr,
                     const char* scratch_directory = ".",
                     const VulkanProbeObservation* vulkan_observation = nullptr,
                     const VulkanSwapchainObservation* vulkan_swapchain_observation = nullptr,
                     const VulkanClearObservation* clear_observation = nullptr,
                     bool vulkan_required = false);
