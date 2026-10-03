#include <iostream>
#include "service/service_core.h"

int main() {
    std::cout << "Starting SentinalService..." << std::endl;

    sentinel::service::ServiceConfig config;
    config.serviceName = "SentinelService";

    sentinel::service::ServiceCore core;
    if (core.initialize(config) != SENTINAL_STATUS_SUCCESS) {
        std::cerr << "Failed to initialize SentinelService" << std::endl;
        return 1;
    }

    if (core.start() != SENTINAL_STATUS_SUCCESS) {
        std::cerr << "Failed to start SentinelService" << std::endl;
        return 1;
    }

    std::cout << "SentinelService running: " << (core.isRunning() ? "YES" : "NO") << std::endl;

    if (core.stop() != SENTINAL_STATUS_SUCCESS) {
        std::cerr << "Failed to stop SentinelService" << std::endl;
        return 1;
    }

    std::cout << "SentinalService foundation build OK" << std::endl;
    return SENTINAL_STATUS_SUCCESS;
}
