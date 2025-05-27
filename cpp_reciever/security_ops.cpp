#include "security_ops.h"
#include <vector>
#include <algorithm> // For std::generate_n
#include <random>    // For std::random_device, std::mt19937, std::uniform_int_distribution
#include <iomanip>   // For std::setw, std::setfill
#include <sstream>   // For std::ostringstream

std::string derive_key_from_pin(const std::string& pin, const std::string& salt, size_t length) {
    std::string combined = salt + pin;
    if (combined.length() < length) {
        combined.resize(length, '0'); // Pad if too short
    }
    return combined.substr(0, length);
}

std::vector<char> xor_encrypt_decrypt(const std::vector<char>& data, const std::string& key) {
    if (key.empty()) return data;
    std::vector<char> result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.length()];
    }
    return result;
}

std::string generate_session_key(size_t length) {
    std::string key(length, '\0');
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, 255);
    std::generate_n(key.begin(), length, [&]() { return static_cast<char>(distribution(generator)); });
    return key;
}

std::string bytes_to_hex(const std::string& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : bytes) {
        oss << std::setw(2) << static_cast<int>(c);
    }
    return oss.str();
}

std::string hex_to_bytes(const std::string& hex) {
    std::string bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

uint32_t calculate_checksum(const char* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; ++i) {
        sum = (sum + static_cast<unsigned char>(data[i])) % 4294967295U; // Modulo a large prime (or 2^32)
    }
    return sum;
}