#include "vulkan_probe.h"
#include <algorithm>
#include <cstring>
#include <cmath>

bool vulkan_candidate_is_usable(const VulkanSurfaceCandidate &c) {
  return c.graphics && c.present && c.swapchain_extension &&
         c.format_count > 0 && c.present_mode_count > 0 &&
         c.min_image_count > 0 &&
         (c.max_image_count == 0 || c.max_image_count >= c.min_image_count);
}

bool vulkan_select_candidate(const VulkanSurfaceCandidate *candidates,
                             std::size_t count,
                             VulkanSurfaceCandidate &selected) {
  if (candidates == nullptr || count == 0)
    return false;
  bool found = false;
  for (std::size_t i = 0; i < count; ++i) {
    if (!vulkan_candidate_is_usable(candidates[i]))
      continue;
    if (!found ||
        candidates[i].physical_device_index < selected.physical_device_index ||
        (candidates[i].physical_device_index ==
             selected.physical_device_index &&
         candidates[i].queue_family < selected.queue_family)) {
      selected = candidates[i];
      found = true;
    }
  }
  return found;
}

bool vulkan_choose_image_count(uint32_t min_count, uint32_t max_count,
                               uint32_t &chosen) {
  if (min_count == 0 || (max_count != 0 && max_count < min_count) ||
      min_count == UINT32_MAX)
    return false;
  const uint32_t requested = min_count + 1;
  chosen = max_count == 0 ? requested
                          : (requested > max_count ? max_count : requested);
  return chosen != 0 && chosen >= min_count &&
         (max_count == 0 || chosen <= max_count);
}

bool vulkan_choose_extent(uint32_t current_width, uint32_t current_height,
                          uint32_t window_width, uint32_t window_height,
                          uint32_t min_width, uint32_t max_width,
                          uint32_t min_height, uint32_t max_height,
                          VulkanSwapchainExtentChoice &chosen) {
  if (min_width == 0 || min_height == 0 || max_width == 0 || max_height == 0 ||
      max_width < min_width || max_height < min_height)
    return false;
  const bool width_variable = current_width == UINT32_MAX;
  const bool height_variable = current_height == UINT32_MAX;
  if (width_variable != height_variable)
    return false;
  if (current_width != UINT32_MAX && current_height != UINT32_MAX) {
    if (current_width == 0 || current_height == 0 ||
        current_width < min_width || current_width > max_width ||
        current_height < min_height || current_height > max_height)
      return false;
    chosen = {current_width, current_height};
    return true;
  }
  if (window_width == 0 || window_height == 0)
    return false;
  const auto clamp = [](uint32_t value, uint32_t low, uint32_t high) {
    return value < low ? low : (high != 0 && value > high ? high : value);
  };
  chosen = {clamp(window_width, min_width, max_width),
            clamp(window_height, min_height, max_height)};
  return true;
}

bool vulkan_choose_format(const VulkanSwapchainFormatChoice *formats,
                          std::size_t count,
                          VulkanSwapchainFormatChoice &chosen) {
  if (formats == nullptr || count == 0)
    return false;
  for (std::size_t i = 0; i < count; ++i)
    if (formats[i].format == 44 && formats[i].color_space == 0) {
      chosen = formats[i];
      return true;
    }
  for (std::size_t i = 0; i < count; ++i)
    if (formats[i].format != 0) {
      chosen = formats[i];
      return true;
    }
  return false;
}

bool vulkan_supports_swapchain_usage(uint32_t supported, uint32_t required) {
  return (supported & required) == required;
}
bool vulkan_acquired_index_valid(uint32_t index, uint32_t image_count) {
  return image_count != 0 && index < image_count;
}
bool vulkan_clear_color_valid(float r, float g, float b, float a) {
  return std::isfinite(r) && std::isfinite(g) && std::isfinite(b) && std::isfinite(a) &&
         r >= 0.0f && r <= 1.0f && g >= 0.0f && g <= 1.0f &&
         b >= 0.0f && b <= 1.0f && a >= 0.0f && a <= 1.0f;
}
VulkanClearPlan vulkan_magenta_clear_plan() { return {}; }
bool vulkan_clear_plan_valid(const VulkanClearPlan &plan) {
  return vulkan_clear_attachment_policy(plan.initial_layout, plan.final_layout,
                                        plan.load_op, plan.store_op) &&
         vulkan_clear_color_valid(plan.r, plan.g, plan.b, plan.a);
}
bool vulkan_clear_attachment_policy(uint32_t initial_layout, uint32_t final_layout,
                                    uint32_t load_op, uint32_t store_op) {
  return initial_layout == 0 && final_layout == 1000001002u && load_op == 1 && store_op == 0;
}
bool vulkan_clear_image_count_valid(uint32_t acquired_index, uint32_t image_count) {
  return image_count > 0 && image_count <= 32 && acquired_index < image_count;
}
bool vulkan_clear_cleanup_order_valid(const uint32_t *destroyed, std::size_t count) {
  return destroyed != nullptr && count == 3 && destroyed[0] == 1 &&
         destroyed[1] == 2 && destroyed[2] == 3;
}
VulkanLifecycleDecision vulkan_lifecycle_decision(bool submit_accepted,
                                                  bool present_accepted,
                                                  bool idle_succeeded) {
  if (!submit_accepted)
    return {VulkanLifecycleResult::pre_submit_failed, true, false};
  if (!idle_succeeded)
    return {VulkanLifecycleResult::idle_failed, false, false};
  if (!present_accepted)
    return {VulkanLifecycleResult::present_failed, true, true};
  return {VulkanLifecycleResult::success, true, true};
}

bool vulkan_choose_fifo(const uint32_t *modes, std::size_t count,
                        uint32_t fifo_mode) {
  if (modes == nullptr || count == 0)
    return false;
  for (std::size_t i = 0; i < count; ++i)
    if (modes[i] == fifo_mode)
      return true;
  return false;
}

bool vulkan_choose_composite_alpha(const uint32_t *supported, std::size_t count,
                                   uint32_t &chosen) {
  if (supported == nullptr || count == 0)
    return false;
  constexpr uint32_t preference[] = {1u, 2u, 4u, 8u};
  for (uint32_t candidate : preference)
    for (std::size_t i = 0; i < count; ++i)
      if ((supported[i] & candidate) != 0) {
        chosen = candidate;
        return true;
      }
  return false;
}

#if defined(__ANDROID__)
#include <android/native_window.h>
#include <array>
#include <cstdio>
#include <vulkan/vulkan.h>

static uint32_t query_instance_api_version() {
  auto enumerate = reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
      vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkEnumerateInstanceVersion"));
  uint32_t version = VK_API_VERSION_1_0;
  if (enumerate != nullptr) {
    uint32_t queried = VK_API_VERSION_1_0;
    if (enumerate(&queried) == VK_SUCCESS)
      version = queried;
  }
  return version;
}

namespace {
constexpr uint32_t kMaxPhysicalDevices = 16, kMaxQueueFamilies = 128;
constexpr uint32_t kMaxInstanceExtensions = 128;
// Android drivers can expose more than 128 device extensions; a physical
// probe observed 190. Keep enumeration bounded at 256 entries (~66 KiB).
constexpr uint32_t kMaxDeviceExtensions = 256;
constexpr uint32_t kMaxFormats = 256, kMaxPresentModes = 256,
                   kMaxSwapchainImages = 32;
} // namespace
const char *vulkan_probe_result_name(VulkanProbeResult r) {
  switch (r) {
  case VulkanProbeResult::ok:
    return "ok";
  case VulkanProbeResult::no_window:
    return "no_window";
  case VulkanProbeResult::required_instance_extension_missing:
    return "required_instance_extension_missing";
  case VulkanProbeResult::instance_creation_failed:
    return "instance_creation_failed";
  case VulkanProbeResult::surface_creation_failed:
    return "surface_creation_failed";
  case VulkanProbeResult::physical_device_count_invalid:
    return "physical_device_count_invalid";
  case VulkanProbeResult::queue_family_count_invalid:
    return "queue_family_count_invalid";
  case VulkanProbeResult::queue_family_query_failed:
    return "queue_family_query_failed";
  case VulkanProbeResult::surface_support_query_failed:
    return "surface_support_query_failed";
  case VulkanProbeResult::surface_capabilities_query_failed:
    return "surface_capabilities_query_failed";
  case VulkanProbeResult::format_count_invalid:
    return "format_count_invalid";
  case VulkanProbeResult::format_query_failed:
    return "format_query_failed";
  case VulkanProbeResult::present_mode_count_invalid:
    return "present_mode_count_invalid";
  case VulkanProbeResult::present_mode_query_failed:
    return "present_mode_query_failed";
  case VulkanProbeResult::device_extension_query_failed:
    return "device_extension_query_failed";
  case VulkanProbeResult::swapchain_extension_missing:
    return "swapchain_extension_missing";
  case VulkanProbeResult::no_usable_candidate:
    return "no_usable_candidate";
  case VulkanProbeResult::device_creation_failed:
    return "device_creation_failed";

  default:
    return "loader_failure";
  }
}
const char *vulkan_swapchain_result_name(VulkanSwapchainResult r) {
  switch (r) {
  case VulkanSwapchainResult::ok:
    return "ok";
  case VulkanSwapchainResult::no_window:
    return "no_window";
  case VulkanSwapchainResult::loader_failure:
    return "loader_failure";

  case VulkanSwapchainResult::runtime_query_failed:
    return "runtime_query_failed";

  case VulkanSwapchainResult::runtime_format_unsupported:
    return "runtime_format_unsupported";

  case VulkanSwapchainResult::runtime_image_count_invalid:
    return "runtime_image_count_invalid";

  case VulkanSwapchainResult::runtime_swapchain_failed:
    return "runtime_swapchain_failed";

  case VulkanSwapchainResult::runtime_image_query_failed:
    return "runtime_image_query_failed";

  case VulkanSwapchainResult::runtime_command_failed:
    return "runtime_command_failed";

  case VulkanSwapchainResult::runtime_acquire_failed:
    return "runtime_acquire_failed";

  case VulkanSwapchainResult::acquired_index_invalid:
    return "acquired_index_invalid";

  case VulkanSwapchainResult::runtime_submit_failed:
    return "runtime_submit_failed";

  case VulkanSwapchainResult::runtime_present_failed:
    return "runtime_present_failed";

  case VulkanSwapchainResult::runtime_idle_failed:
    return "runtime_idle_failed";
  }
  return "unknown";
}

static VulkanSwapchainResult
run_one_swapchain(VkPhysicalDevice physical, VkDevice device,
                  VkSurfaceKHR surface, uint32_t family, ANativeWindow *window,
                  VulkanSwapchainObservation &o, VulkanClearObservation &clear) {
  VkSurfaceCapabilitiesKHR caps{};

  if (vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical, surface, &caps) !=
      VK_SUCCESS)
    return VulkanSwapchainResult::runtime_query_failed;

  uint32_t fc = 0, mc = 0;

  if (vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &fc, nullptr) !=
          VK_SUCCESS ||
      fc == 0 || fc > kMaxFormats ||
      vkGetPhysicalDeviceSurfacePresentModesKHR(physical, surface, &mc,
                                                nullptr) != VK_SUCCESS ||
      mc == 0 || mc > kMaxPresentModes)
    return VulkanSwapchainResult::runtime_query_failed;

  std::array<VkSurfaceFormatKHR, kMaxFormats> formats{};
  std::array<VkPresentModeKHR, kMaxPresentModes> modes{};

  uint32_t fcap = fc, mcap = mc;

  if (vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &fcap,
                                           formats.data()) != VK_SUCCESS ||
      fcap != fc ||
      vkGetPhysicalDeviceSurfacePresentModesKHR(physical, surface, &mcap,
                                                modes.data()) != VK_SUCCESS ||
      mcap != mc)
    return VulkanSwapchainResult::runtime_query_failed;

  VulkanSwapchainFormatChoice choices[kMaxFormats]{};
  for (uint32_t i = 0; i < fc; i++)
    choices[i] = {formats[i].format, formats[i].colorSpace};

  VulkanSwapchainFormatChoice format{};
  if (!vulkan_choose_format(choices, fc, format))
    return VulkanSwapchainResult::runtime_format_unsupported;

  bool color_attachment = false;

  VkFormatProperties fp{};
  vkGetPhysicalDeviceFormatProperties(physical, VkFormat(format.format), &fp);

  color_attachment =
      (fp.optimalTilingFeatures & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT) != 0;

  uint32_t mode_values[kMaxPresentModes]{};
  for (uint32_t i = 0; i < mc; i++)
    mode_values[i] = uint32_t(modes[i]);

  if (!vulkan_supports_swapchain_usage(caps.supportedUsageFlags,
                                       VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT) ||
      !color_attachment ||
      !vulkan_choose_fifo(mode_values, mc, VK_PRESENT_MODE_FIFO_KHR))
    return VulkanSwapchainResult::runtime_format_unsupported;

  uint32_t chosen_count = 0;
  if (!vulkan_choose_image_count(caps.minImageCount, caps.maxImageCount,
                                 chosen_count))
    return VulkanSwapchainResult::runtime_image_count_invalid;

  int32_t ww = ANativeWindow_getWidth(window),
          wh = ANativeWindow_getHeight(window);

  VulkanSwapchainExtentChoice extent{};

  if (!vulkan_choose_extent(
          caps.currentExtent.width, caps.currentExtent.height,
          ww > 0 ? uint32_t(ww) : 0, wh > 0 ? uint32_t(wh) : 0,
          caps.minImageExtent.width, caps.maxImageExtent.width,
          caps.minImageExtent.height, caps.maxImageExtent.height, extent))
    return VulkanSwapchainResult::runtime_query_failed;

  uint32_t alpha_bits[] = {caps.supportedCompositeAlpha};
  uint32_t alpha = 0;

  if (!vulkan_choose_composite_alpha(alpha_bits, 1, alpha))
    return VulkanSwapchainResult::runtime_query_failed;

  o.chosen_image_count = chosen_count;
  o.chosen_format = format.format;
  o.chosen_color_space = format.color_space;
  o.chosen_present_mode = VK_PRESENT_MODE_FIFO_KHR;
  o.chosen_composite_alpha = alpha;
  o.width = extent.width;
  o.height = extent.height;

  VkSwapchainCreateInfoKHR sci{};
  sci.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
  sci.surface = surface;
  sci.minImageCount = chosen_count;
  sci.imageFormat = VkFormat(format.format);
  sci.imageColorSpace = VkColorSpaceKHR(format.color_space);
  sci.imageExtent.width = extent.width;
  sci.imageExtent.height = extent.height;
  sci.imageArrayLayers = 1;
  sci.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
  sci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
  sci.preTransform = caps.currentTransform;
  sci.compositeAlpha = VkCompositeAlphaFlagBitsKHR(alpha);
  sci.presentMode = VK_PRESENT_MODE_FIFO_KHR;
  sci.clipped = VK_TRUE;

  VkSwapchainKHR swapchain = VK_NULL_HANDLE;
  VkCommandPool pool = VK_NULL_HANDLE;
  VkSemaphore acquire = VK_NULL_HANDLE;
  VkSemaphore present = VK_NULL_HANDLE;
  VkRenderPass render_pass = VK_NULL_HANDLE;
  VkImageView image_view = VK_NULL_HANDLE;
  VkFramebuffer framebuffer = VK_NULL_HANDLE;
  bool submission_accepted = false;
  const VulkanClearPlan clear_plan = vulkan_magenta_clear_plan();
  if (!vulkan_clear_plan_valid(clear_plan))
    return VulkanSwapchainResult::runtime_command_failed;
  const auto cleanup_owned_resources = [&]() {
    if (framebuffer != VK_NULL_HANDLE) { vkDestroyFramebuffer(device, framebuffer, nullptr); framebuffer = VK_NULL_HANDLE; clear.cleanup_order[clear.cleanup_order_count++] = 1; }
    if (image_view != VK_NULL_HANDLE) { vkDestroyImageView(device, image_view, nullptr); image_view = VK_NULL_HANDLE; clear.cleanup_order[clear.cleanup_order_count++] = 2; }
    if (render_pass != VK_NULL_HANDLE) { vkDestroyRenderPass(device, render_pass, nullptr); render_pass = VK_NULL_HANDLE; clear.cleanup_order[clear.cleanup_order_count++] = 3; }
    if (present != VK_NULL_HANDLE) {
      vkDestroySemaphore(device, present, nullptr);
      present = VK_NULL_HANDLE;
    }
    if (acquire != VK_NULL_HANDLE) {
      vkDestroySemaphore(device, acquire, nullptr);
      acquire = VK_NULL_HANDLE;
    }
    if (pool != VK_NULL_HANDLE) {
      vkDestroyCommandPool(device, pool, nullptr);
      pool = VK_NULL_HANDLE;
    }
    if (swapchain != VK_NULL_HANDLE) {
      vkDestroySwapchainKHR(device, swapchain, nullptr);
      swapchain = VK_NULL_HANDLE;
    }
  };
  if (vkCreateSwapchainKHR(device, &sci, nullptr, &swapchain) != VK_SUCCESS)
    return VulkanSwapchainResult::runtime_swapchain_failed;

  VkResult result = VK_SUCCESS;
  uint32_t image_count = 0;
  result = vkGetSwapchainImagesKHR(device, swapchain, &image_count, nullptr);

  std::array<VkImage, kMaxSwapchainImages> images{};
  if (result != VK_SUCCESS || image_count == 0 ||
      image_count > kMaxSwapchainImages) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_image_query_failed;
  }
  uint32_t actual = image_count;
  result = vkGetSwapchainImagesKHR(device, swapchain, &actual, images.data());
  if (result != VK_SUCCESS || actual != image_count) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_image_query_failed;
  }
  o.actual_image_count = actual;

  VkQueue queue = VK_NULL_HANDLE;
  vkGetDeviceQueue(device, family, 0, &queue);
  if (!queue) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_command_failed;
  }
  pool = VK_NULL_HANDLE;
  VkCommandPoolCreateInfo pi{};
  pi.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
  pi.queueFamilyIndex = family;
  if (vkCreateCommandPool(device, &pi, nullptr, &pool) != VK_SUCCESS) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_command_failed;
  }
  VkCommandBuffer cmd = VK_NULL_HANDLE;
  VkCommandBufferAllocateInfo ai{};
  ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
  ai.commandPool = pool;
  ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
  ai.commandBufferCount = 1;
  if (vkAllocateCommandBuffers(device, &ai, &cmd) != VK_SUCCESS) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_command_failed;
  }
  acquire = VK_NULL_HANDLE;
  present = VK_NULL_HANDLE;
  VkSemaphoreCreateInfo si{};
  si.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
  if (vkCreateSemaphore(device, &si, nullptr, &acquire) != VK_SUCCESS ||
      vkCreateSemaphore(device, &si, nullptr, &present) != VK_SUCCESS) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_command_failed;
  }
  result = vkAcquireNextImageKHR(device, swapchain, 2000000000ULL, acquire,
                                 VK_NULL_HANDLE, &o.acquired_image_index);

  if (result == VK_SUBOPTIMAL_KHR)
    o.acquire_suboptimal = true;

  if (result != VK_SUCCESS && result != VK_SUBOPTIMAL_KHR) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_acquire_failed;
  }
  if (!vulkan_acquired_index_valid(o.acquired_image_index, actual)) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::acquired_index_invalid;
  }
  VkCommandBufferBeginInfo bi{};
  bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
  bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
  VkAttachmentDescription attachment{}; attachment.format = VkFormat(format.format); attachment.samples = VK_SAMPLE_COUNT_1_BIT; attachment.loadOp = VkAttachmentLoadOp(clear_plan.load_op); attachment.storeOp = VkAttachmentStoreOp(clear_plan.store_op); attachment.initialLayout = VkImageLayout(clear_plan.initial_layout); attachment.finalLayout = VkImageLayout(clear_plan.final_layout);
  VkAttachmentReference reference{0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
  VkSubpassDescription subpass{}; subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS; subpass.colorAttachmentCount = 1; subpass.pColorAttachments = &reference;
  VkRenderPassCreateInfo render_info{}; render_info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO; render_info.attachmentCount = 1; render_info.pAttachments = &attachment; render_info.subpassCount = 1; render_info.pSubpasses = &subpass;
  if (vkCreateRenderPass(device, &render_info, nullptr, &render_pass) != VK_SUCCESS) { cleanup_owned_resources(); return VulkanSwapchainResult::runtime_command_failed; } clear.render_pass_created = true;
  VkImageViewCreateInfo view_info{}; view_info.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO; view_info.image = images[o.acquired_image_index]; view_info.viewType = VK_IMAGE_VIEW_TYPE_2D; view_info.format = VkFormat(format.format); view_info.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
  if (vkCreateImageView(device, &view_info, nullptr, &image_view) != VK_SUCCESS) { cleanup_owned_resources(); return VulkanSwapchainResult::runtime_command_failed; } clear.image_view_created = true;
  VkFramebufferCreateInfo fb_info{}; fb_info.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO; fb_info.renderPass = render_pass; fb_info.attachmentCount = 1; fb_info.pAttachments = &image_view; fb_info.width = extent.width; fb_info.height = extent.height; fb_info.layers = 1;
  if (vkCreateFramebuffer(device, &fb_info, nullptr, &framebuffer) != VK_SUCCESS) { cleanup_owned_resources(); return VulkanSwapchainResult::runtime_command_failed; } clear.framebuffer_created = true;
  if (vkBeginCommandBuffer(cmd, &bi) != VK_SUCCESS) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_command_failed;
  }
  clear.r = clear_plan.r; clear.g = clear_plan.g; clear.b = clear_plan.b; clear.a = clear_plan.a;
  VkClearValue clear_value{}; clear_value.color = {{clear.r, clear.g, clear.b, clear.a}};
  VkRenderPassBeginInfo render_begin{}; render_begin.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO; render_begin.renderPass = render_pass; render_begin.framebuffer = framebuffer; render_begin.renderArea.extent = {extent.width, extent.height}; render_begin.clearValueCount = 1; render_begin.pClearValues = &clear_value;
  vkCmdBeginRenderPass(cmd, &render_begin, VK_SUBPASS_CONTENTS_INLINE); vkCmdEndRenderPass(cmd); clear.command_recorded = true;
  if (vkEndCommandBuffer(cmd) != VK_SUCCESS) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_command_failed;
  }
  VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT;
  VkSubmitInfo submit{};
  submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
  submit.waitSemaphoreCount = 1;
  submit.pWaitSemaphores = &acquire;
  submit.pWaitDstStageMask = &wait_stage;
  submit.commandBufferCount = 1;
  submit.pCommandBuffers = &cmd;
  submit.signalSemaphoreCount = 1;
  submit.pSignalSemaphores = &present;
  if (vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS) {
    cleanup_owned_resources();
    return VulkanSwapchainResult::runtime_submit_failed;
  }
  submission_accepted = true;
  o.submit_accepted = submission_accepted;
  clear.submit_accepted = submission_accepted;

  VkPresentInfoKHR present_info{};

  present_info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;

  present_info.waitSemaphoreCount = 1;

  present_info.pWaitSemaphores = &present;

  present_info.swapchainCount = 1;

  present_info.pSwapchains = &swapchain;

  present_info.pImageIndices = &o.acquired_image_index;

  VkResult present_result = vkQueuePresentKHR(queue, &present_info);

  if (present_result == VK_SUBOPTIMAL_KHR)
    o.present_suboptimal = true;

  const bool present_accepted =
      present_result == VK_SUCCESS || present_result == VK_SUBOPTIMAL_KHR;

  o.present_accepted = present_accepted;
  clear.present_accepted = present_accepted;

  const bool idle_succeeded = vkQueueWaitIdle(queue) == VK_SUCCESS;

  const VulkanLifecycleDecision decision = vulkan_lifecycle_decision(
      o.submit_accepted, present_accepted, idle_succeeded);

  if (!decision.cleanup_allowed)
    return VulkanSwapchainResult::runtime_idle_failed;

  o.work_complete = decision.work_complete;
  clear.work_complete = decision.work_complete;

  cleanup_owned_resources();
  o.cleanup_complete = true;
  clear.cleanup_complete = true;

  return present_accepted ? VulkanSwapchainResult::ok
                          : VulkanSwapchainResult::runtime_present_failed;
}

VulkanProbeResult vulkan_prefer_probe_failure(VulkanProbeResult current,
                                              VulkanProbeResult candidate) {
  auto rank = [](VulkanProbeResult r) {
    switch (r) {
    case VulkanProbeResult::device_creation_failed:
      return 100;
    case VulkanProbeResult::surface_support_query_failed:
      return 90;
    case VulkanProbeResult::present_mode_query_failed:
      return 80;
    case VulkanProbeResult::present_mode_count_invalid:
      return 79;
    case VulkanProbeResult::format_query_failed:
      return 70;
    case VulkanProbeResult::format_count_invalid:
      return 69;
    case VulkanProbeResult::surface_capabilities_query_failed:
      return 60;
    case VulkanProbeResult::swapchain_extension_missing:
      return 50;
    case VulkanProbeResult::device_extension_query_failed:
      return 49;
    case VulkanProbeResult::queue_family_query_failed:
      return 40;
    case VulkanProbeResult::queue_family_count_invalid:
      return 39;
    case VulkanProbeResult::no_usable_candidate:
      return 1;
    default:
      return 0;
    }
  };
  return rank(candidate) > rank(current) ? candidate : current;
}

int run_vulkan_surface_device_probe(ANativeWindow *window,
                                    VulkanProbeObservation &o,
                                    VulkanSwapchainObservation &swapchain, VulkanClearObservation &clear) {
  o = {};
  swapchain = {};
  o.api_version = query_instance_api_version();
  if (!window) {
    o.result = VulkanProbeResult::no_window;
    swapchain.result = VulkanSwapchainResult::no_window;
    return -1;
  }
  VkInstance instance = VK_NULL_HANDLE;
  VkSurfaceKHR surface = VK_NULL_HANDLE;
  VkDevice device = VK_NULL_HANDLE;
  int rc = -1;
  uint32_t pc = 0, pcap = 0;
  VulkanProbeResult best_failure = VulkanProbeResult::no_usable_candidate;
  std::array<VkPhysicalDevice, kMaxPhysicalDevices> physical{};
  auto fail = [&](VulkanProbeResult r) {
    o.result = r;
    return rc;
  };
  uint32_t ext_count = 0;
  if (vkEnumerateInstanceExtensionProperties(nullptr, &ext_count, nullptr) !=
          VK_SUCCESS ||
      ext_count == 0 || ext_count > kMaxInstanceExtensions)
    return fail(VulkanProbeResult::required_instance_extension_missing);
  std::array<VkExtensionProperties, kMaxInstanceExtensions> exts{};
  uint32_t ext_capacity = ext_count;
  VkResult vr = vkEnumerateInstanceExtensionProperties(nullptr, &ext_capacity,
                                                       exts.data());
  if (vr != VK_SUCCESS || ext_capacity != ext_count ||
      ext_capacity > kMaxInstanceExtensions)
    return fail(VulkanProbeResult::required_instance_extension_missing);
  bool has_surface = false, has_android = false;
  for (uint32_t i = 0; i < ext_capacity; i++) {
    has_surface |=
        std::strcmp(exts[i].extensionName, VK_KHR_SURFACE_EXTENSION_NAME) == 0;
    has_android |= std::strcmp(exts[i].extensionName,
                               VK_KHR_ANDROID_SURFACE_EXTENSION_NAME) == 0;
  }
  if (!has_surface || !has_android)
    return fail(VulkanProbeResult::required_instance_extension_missing);
  VkApplicationInfo app{};
  app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
  app.pApplicationName = "totk-probe";
  app.applicationVersion = 1;
  app.pEngineName = "totk";
  app.engineVersion = 1;
  app.apiVersion = VK_API_VERSION_1_0;
  const char *names[] = {VK_KHR_SURFACE_EXTENSION_NAME,
                         VK_KHR_ANDROID_SURFACE_EXTENSION_NAME};
  VkInstanceCreateInfo ci{};
  ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
  ci.pApplicationInfo = &app;
  ci.enabledExtensionCount = 2;
  ci.ppEnabledExtensionNames = names;
  if (vkCreateInstance(&ci, nullptr, &instance) != VK_SUCCESS)
    return fail(VulkanProbeResult::instance_creation_failed);
  VkAndroidSurfaceCreateInfoKHR sci{};
  sci.sType = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR;
  sci.window = window;
  if (vkCreateAndroidSurfaceKHR(instance, &sci, nullptr, &surface) !=
      VK_SUCCESS) {
    o.result = VulkanProbeResult::surface_creation_failed;
    goto cleanup;
  }
  pc = 0;
  vr = vkEnumeratePhysicalDevices(instance, &pc, nullptr);
  if (vr != VK_SUCCESS || pc == 0 || pc > kMaxPhysicalDevices) {
    o.result = VulkanProbeResult::physical_device_count_invalid;
    goto cleanup;
  }
  pcap = pc;
  vr = vkEnumeratePhysicalDevices(instance, &pcap, physical.data());
  if (vr != VK_SUCCESS || pcap != pc || pcap == 0 ||
      pcap > kMaxPhysicalDevices) {
    o.result = VulkanProbeResult::physical_device_count_invalid;
    goto cleanup;
  }
  o.physical_device_count = pcap;
  for (uint32_t p = 0; p < pcap; ++p) {
    o.last_physical_device_index = p;
    uint32_t qc = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical[p], &qc, nullptr);
    o.queue_family_count = qc;
    if (qc == 0 || qc > kMaxQueueFamilies) {
      best_failure = vulkan_prefer_probe_failure(
          best_failure, VulkanProbeResult::queue_family_count_invalid);
      continue;
    }
    std::array<VkQueueFamilyProperties, kMaxQueueFamilies> q{};
    uint32_t qcap = qc;
    vkGetPhysicalDeviceQueueFamilyProperties(physical[p], &qcap, q.data());
    if (qcap != qc || qcap > kMaxQueueFamilies) {
      best_failure = vulkan_prefer_probe_failure(
          best_failure, VulkanProbeResult::queue_family_query_failed);
      continue;
    }
    o.graphics_queue_count = o.present_queue_count =
        o.graphics_present_queue_count = 0;
    for (uint32_t f = 0; f < qcap; ++f) {
      if (q[f].queueFlags & VK_QUEUE_GRAPHICS_BIT)
        ++o.graphics_queue_count;
      VkBool32 present = VK_FALSE;
      if (vkGetPhysicalDeviceSurfaceSupportKHR(physical[p], f, surface,
                                               &present) != VK_SUCCESS) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::surface_support_query_failed);
        goto next_device;
      }
      if (present == VK_TRUE)
        ++o.present_queue_count;
      if ((q[f].queueFlags & VK_QUEUE_GRAPHICS_BIT) && present == VK_TRUE)
        ++o.graphics_present_queue_count;
    }
    {
      uint32_t dc = 0;
      vr = vkEnumerateDeviceExtensionProperties(physical[p], nullptr, &dc,
                                                nullptr);
      o.device_extension_count = dc;
      if (vr != VK_SUCCESS || dc == 0 || dc > kMaxDeviceExtensions) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::device_extension_query_failed);
        goto next_device;
      }
      std::array<VkExtensionProperties, kMaxDeviceExtensions> de{};
      uint32_t dcap = dc;
      vr = vkEnumerateDeviceExtensionProperties(physical[p], nullptr, &dcap,
                                                de.data());
      if (vr != VK_SUCCESS || dcap != dc || dcap > kMaxDeviceExtensions) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::device_extension_query_failed);
        goto next_device;
      }
      bool swap = false;
      for (uint32_t i = 0; i < dcap; ++i)
        swap |= std::strcmp(de[i].extensionName,
                            VK_KHR_SWAPCHAIN_EXTENSION_NAME) == 0;
      o.swapchain_extension = swap;
      if (!swap) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::swapchain_extension_missing);
        goto next_device;
      }
      VkSurfaceCapabilitiesKHR caps{};
      if (vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical[p], surface,
                                                    &caps) != VK_SUCCESS) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::surface_capabilities_query_failed);
        goto next_device;
      }
      uint32_t fc = 0;
      vr = vkGetPhysicalDeviceSurfaceFormatsKHR(physical[p], surface, &fc,
                                                nullptr);
      o.format_count = fc;
      if (vr != VK_SUCCESS || fc == 0 || fc > kMaxFormats) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::format_count_invalid);
        goto next_device;
      }
      std::array<VkSurfaceFormatKHR, kMaxFormats> formats{};
      uint32_t fcap = fc;
      vr = vkGetPhysicalDeviceSurfaceFormatsKHR(physical[p], surface, &fcap,
                                                formats.data());
      if (vr != VK_SUCCESS || fcap != fc || fcap > kMaxFormats) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::format_query_failed);
        goto next_device;
      }
      uint32_t mc = 0;
      vr = vkGetPhysicalDeviceSurfacePresentModesKHR(physical[p], surface, &mc,
                                                     nullptr);
      o.present_mode_count = mc;
      if (vr != VK_SUCCESS || mc == 0 || mc > kMaxPresentModes) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::present_mode_count_invalid);
        goto next_device;
      }
      std::array<VkPresentModeKHR, kMaxPresentModes> modes{};
      uint32_t mcap = mc;
      vr = vkGetPhysicalDeviceSurfacePresentModesKHR(physical[p], surface,
                                                     &mcap, modes.data());
      if (vr != VK_SUCCESS || mcap != mc || mcap > kMaxPresentModes) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::present_mode_query_failed);
        goto next_device;
      }
      std::array<VulkanSurfaceCandidate, kMaxQueueFamilies> candidates{};
      size_t n = 0;
      for (uint32_t f = 0; f < qcap; ++f) {
        VkBool32 present = VK_FALSE;
        if (vkGetPhysicalDeviceSurfaceSupportKHR(physical[p], f, surface,
                                                 &present) != VK_SUCCESS) {
          best_failure = vulkan_prefer_probe_failure(
              best_failure, VulkanProbeResult::surface_support_query_failed);
          n = 0;
          break;
        }
        candidates[n++] = {p,
                           f,
                           fc,
                           mc,
                           caps.minImageCount,
                           caps.maxImageCount,
                           (q[f].queueFlags & VK_QUEUE_GRAPHICS_BIT) != 0,
                           present == VK_TRUE,
                           swap};
      }
      VulkanSurfaceCandidate selected{};
      if (!vulkan_select_candidate(candidates.data(), n, selected)) {
        best_failure = vulkan_prefer_probe_failure(
            best_failure, VulkanProbeResult::no_usable_candidate);
        goto next_device;
      }
      VkPhysicalDeviceProperties props{};
      vkGetPhysicalDeviceProperties(physical[p], &props);
      std::snprintf(o.device_name, sizeof(o.device_name), "%s",
                    props.deviceName);
      o.physical_device_index = p;
      o.queue_family = selected.queue_family;
      o.min_image_count = selected.min_image_count;
      o.max_image_count = selected.max_image_count;
      o.width = caps.currentExtent.width;
      o.height = caps.currentExtent.height;
      float priority = 1.0f;
      VkDeviceQueueCreateInfo qi{};
      qi.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
      qi.queueFamilyIndex = selected.queue_family;
      qi.queueCount = 1;
      qi.pQueuePriorities = &priority;
      const char *swap_name = VK_KHR_SWAPCHAIN_EXTENSION_NAME;
      VkDeviceCreateInfo di{};
      di.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
      di.queueCreateInfoCount = 1;
      di.pQueueCreateInfos = &qi;
      di.enabledExtensionCount = 1;
      di.ppEnabledExtensionNames = &swap_name;
      if (vkCreateDevice(physical[p], &di, nullptr, &device) == VK_SUCCESS) {
        o.result = VulkanProbeResult::ok;
        const VulkanSwapchainResult runtime =
            run_one_swapchain(physical[p], device, surface,
                              selected.queue_family, window, swapchain, clear);
        swapchain.result = runtime;
        rc = runtime == VulkanSwapchainResult::ok ? 0 : -1;
        goto cleanup;
      }
      best_failure = vulkan_prefer_probe_failure(
          best_failure, VulkanProbeResult::device_creation_failed);
    }
  next_device:;
  }
  o.result = best_failure;
cleanup:
  if (swapchain.result == VulkanSwapchainResult::runtime_idle_failed)
    return rc;
  if (device)
    vkDestroyDevice(device, nullptr);
  if (surface)
    vkDestroySurfaceKHR(instance, surface, nullptr);
  if (instance)
    vkDestroyInstance(instance, nullptr);
  return rc;
}
#endif
