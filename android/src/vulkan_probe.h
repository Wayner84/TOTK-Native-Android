#pragma once

#include <cstddef>
#include <cstdint>
struct VulkanSurfaceCandidate {
  uint32_t physical_device_index = 0;
  uint32_t queue_family = 0;
  uint32_t format_count = 0;
  uint32_t present_mode_count = 0;
  uint32_t min_image_count = 0;
  uint32_t max_image_count = 0;
  bool graphics = false;
  bool present = false;
  bool swapchain_extension = false;
};

bool vulkan_candidate_is_usable(const VulkanSurfaceCandidate &candidate);
bool vulkan_select_candidate(const VulkanSurfaceCandidate *candidates,
                             std::size_t count,
                             VulkanSurfaceCandidate &selected);

struct VulkanSwapchainFormatChoice {
  uint32_t format = 0;
  uint32_t color_space = 0;
};
struct VulkanSwapchainExtentChoice {
  uint32_t width = 0;
  uint32_t height = 0;
};
bool vulkan_choose_image_count(uint32_t min_count, uint32_t max_count,
                               uint32_t &chosen);
bool vulkan_choose_extent(uint32_t current_width, uint32_t current_height,
                          uint32_t window_width, uint32_t window_height,
                          uint32_t min_width, uint32_t max_width,
                          uint32_t min_height, uint32_t max_height,
                          VulkanSwapchainExtentChoice &chosen);
bool vulkan_choose_format(const VulkanSwapchainFormatChoice *formats,
                          std::size_t count,
                          VulkanSwapchainFormatChoice &chosen);
bool vulkan_choose_fifo(const uint32_t *modes, std::size_t count,
                        uint32_t fifo_mode);
bool vulkan_choose_composite_alpha(const uint32_t *supported, std::size_t count,
                                   uint32_t &chosen);
bool vulkan_supports_swapchain_usage(uint32_t supported, uint32_t required);
bool vulkan_acquired_index_valid(uint32_t index, uint32_t image_count);
bool vulkan_clear_color_valid(float r, float g, float b, float a);
struct VulkanClearPlan {
  uint32_t initial_layout = 0;
  uint32_t final_layout = 1000001002u;
  uint32_t load_op = 1;
  uint32_t store_op = 0;
  float r = 1.0f, g = 0.0f, b = 1.0f, a = 1.0f;
};
VulkanClearPlan vulkan_magenta_clear_plan();
bool vulkan_clear_plan_valid(const VulkanClearPlan &plan);
bool vulkan_clear_attachment_policy(uint32_t initial_layout, uint32_t final_layout,
                                    uint32_t load_op, uint32_t store_op);
bool vulkan_clear_image_count_valid(uint32_t acquired_index, uint32_t image_count);
bool vulkan_clear_cleanup_order_valid(const uint32_t *destroyed, std::size_t count);
enum class VulkanLifecycleResult : uint32_t {
  pre_submit_failed,
  present_failed,
  idle_failed,
  success
};
struct VulkanLifecycleDecision {
  VulkanLifecycleResult result;
  bool cleanup_allowed;
  bool work_complete;
};
VulkanLifecycleDecision vulkan_lifecycle_decision(bool submit_accepted,
                                                  bool present_accepted,
                                                  bool idle_succeeded);

#if defined(__ANDROID__)
struct ANativeWindow;
enum class VulkanProbeResult : uint32_t {
  ok,
  no_window,
  loader_failure,
  required_instance_extension_missing,
  instance_creation_failed,
  surface_creation_failed,
  physical_device_query_failed,
  physical_device_count_invalid,
  queue_family_count_invalid,
  queue_family_query_failed,
  surface_support_query_failed,
  surface_capabilities_query_failed,
  format_count_invalid,
  format_query_failed,
  present_mode_count_invalid,
  present_mode_query_failed,
  device_extension_query_failed,
  swapchain_extension_missing,
  no_usable_candidate,
  device_creation_failed
};
enum class VulkanSwapchainResult : uint32_t {
  ok,
  no_window,
  loader_failure,
  runtime_query_failed,
  runtime_format_unsupported,
  runtime_image_count_invalid,
  runtime_swapchain_failed,
  runtime_image_query_failed,
  runtime_command_failed,
  runtime_acquire_failed,
  acquired_index_invalid,
  runtime_submit_failed,
  runtime_present_failed,
  runtime_idle_failed
};
VulkanProbeResult vulkan_prefer_probe_failure(VulkanProbeResult current,
                                              VulkanProbeResult candidate);
struct VulkanProbeObservation {
  VulkanProbeResult result = VulkanProbeResult::loader_failure;
  uint32_t api_version = 0;
  uint32_t physical_device_count = 0;
  uint32_t last_physical_device_index = 0;
  uint32_t queue_family_count = 0;
  uint32_t graphics_queue_count = 0;
  uint32_t present_queue_count = 0;
  uint32_t graphics_present_queue_count = 0;
  uint32_t device_extension_count = 0;
  bool swapchain_extension = false;
  uint32_t physical_device_index = 0;
  uint32_t queue_family = 0;
  uint32_t min_image_count = 0;
  uint32_t max_image_count = 0;
  uint32_t format_count = 0;
  uint32_t present_mode_count = 0;
  uint32_t width = 0;
  uint32_t height = 0;
  char device_name[128]{};
};
struct VulkanSwapchainObservation {
  VulkanSwapchainResult result = VulkanSwapchainResult::loader_failure;
  uint32_t width = 0, height = 0, chosen_image_count = 0,
           actual_image_count = 0;
  uint32_t acquired_image_index = 0, chosen_format = 0, chosen_color_space = 0;
  uint32_t chosen_present_mode = 0, chosen_composite_alpha = 0;
  bool acquire_suboptimal = false, present_suboptimal = false;
  bool submit_accepted = false, present_accepted = false, work_complete = false,
       cleanup_complete = false;
};
struct VulkanClearObservation {
  float r = 1.0f, g = 0.0f, b = 1.0f, a = 1.0f;
  bool render_pass_created = false;
  bool image_view_created = false;
  bool framebuffer_created = false;
  bool command_recorded = false;
  bool submit_accepted = false;
  bool present_accepted = false;
  bool work_complete = false;
  bool cleanup_complete = false;
  uint32_t cleanup_order[3]{};
  uint32_t cleanup_order_count = 0;
};
const char *vulkan_probe_result_name(VulkanProbeResult result);
const char *vulkan_swapchain_result_name(VulkanSwapchainResult result);
int run_vulkan_surface_device_probe(ANativeWindow *window,
                                    VulkanProbeObservation &foundation,
                                    VulkanSwapchainObservation &swapchain,
                                    VulkanClearObservation &clear);
#endif
