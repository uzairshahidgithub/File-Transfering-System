#ifndef SECURITY_OPS_H
#define SECURITY_OPS_H

#include <string>
#include <vector>
#include <cstdint> // For uint32_t

// "Hashes" a PIN by appending a salt and taking a substring.
// NOT cryptographically secure, for simplicity as requested.
std::string derive_key_from_pin(const std::string& pin, const std::string& salt, size_t length);

// Performs XOR encryption/decryption.
std::vector<char> xor_encrypt_decrypt(const std::vector<char>& data, const std::string& key);

// Generates a random session key.
std::string generate_session_key(size_t length);

// Converts bytes to hex string and vice-versa
std::string bytes_to_hex(const std::string& bytes);
std::string hex_to_bytes(const std::string& hex);

// Calculates a simple checksum.
uint32_t calculate_checksum(const char* data, size_t length);

#endif // SECURITY_OPS_H