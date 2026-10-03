#include "service/logger.h"
#include <iostream>

namespace sentinel::service {

void ConsoleLogger::log(LogLevel level, const std::string& message) {
    const char* prefix = "[INFO]";
    switch (level) {
        case LogLevel::Info:    prefix = "[INFO]"; break;
        case LogLevel::Warning: prefix = "[WARN]"; break;
        case LogLevel::Error:   prefix = "[ERROR]"; break;
    }
    std::cout << prefix << " " << message << std::endl;
}

} // namespace sentinel::service
