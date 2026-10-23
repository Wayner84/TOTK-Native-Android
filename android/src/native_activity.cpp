#include "loader_probe.h"
#include <android/native_activity.h>
#include <android/native_window.h>
#include <android_native_app_glue.h>
#include <android/log.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>

extern "C" void android_main(android_app* app) {
    const std::filesystem::path output = std::filesystem::path(app->activity->internalDataPath) / "loader-probe.log";
    FILE* stream = std::freopen(output.string().c_str(), "w", stdout);
    if (stream) std::setvbuf(stream, nullptr, _IOLBF, 0);
    ANativeWindow* strong_window = nullptr;
    VulkanProbeObservation observation{};
    VulkanSwapchainObservation swapchain_observation{};
    VulkanClearObservation clear_observation{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool terminated = false;
    while (!strong_window && !terminated && std::chrono::steady_clock::now() < deadline) {
        int events = 0; android_poll_source* source = nullptr;
        const int poll = ALooper_pollOnce(100, nullptr, &events, reinterpret_cast<void**>(&source));
        if (poll >= 0 && source) source->process(app, source);
        if (app->destroyRequested != 0) { terminated = true; break; }
        if (app->window) { ANativeWindow_acquire(app->window); strong_window = app->window; break; }
    }
    if (strong_window) {
        run_vulkan_surface_device_probe(strong_window, observation, swapchain_observation, clear_observation);
        ANativeWindow_release(strong_window);
    } else {
        observation.result = VulkanProbeResult::no_window;
        swapchain_observation.result = VulkanSwapchainResult::no_window;
    }
    const std::array<std::filesystem::path, 3> modules = {
        std::filesystem::path(app->activity->internalDataPath) / "private-module-0.elf",
        std::filesystem::path(app->activity->internalDataPath) / "private-module-1.elf",
        std::filesystem::path(app->activity->internalDataPath) / "private-module-2.elf"};
    const std::filesystem::path reloc = std::filesystem::path(app->activity->internalDataPath) / "private-relocations.bin";
    const std::array<std::string,3> paths = {modules[0].string(),modules[1].string(),modules[2].string()};
    const std::array<const char*,3> path_ptrs = {paths[0].c_str(),paths[1].c_str(),paths[2].c_str()};
    const std::string relocation_string = reloc.string();
    const std::filesystem::path binding = std::filesystem::path(app->activity->internalDataPath) / "entry-binding.bin";
    const std::string binding_string = binding.string();
    const bool complete = std::filesystem::exists(modules[0]) && std::filesystem::exists(modules[1]) && std::filesystem::exists(modules[2]) && std::filesystem::exists(reloc) && std::filesystem::exists(binding);
    const int result = run_loader_probe(complete ? path_ptrs.data() : nullptr, complete ? path_ptrs.size() : 0,
        complete ? relocation_string.c_str() : nullptr, complete ? binding_string.c_str() : nullptr, app->activity->internalDataPath, &observation, &swapchain_observation, &clear_observation, true);
    std::fflush(stdout);
    __android_log_print(result == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, "TotkLoaderProbe", "probe finished rc=%d log=%s", result, output.string().c_str());
    ANativeActivity_finish(app->activity);
}
