#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>

// Client to Server
const std::string MSG_C_PIN_PREFIX = "PIN:";
const std::string MSG_C_FILE_HEADER_PREFIX = "FHDR:";

// Server to Client
const std::string MSG_S_AUTH_SUCCESS = "AUTH_SUCCESS\n";
const std::string MSG_S_AUTH_FAIL = "AUTH_FAIL\n";
const std::string MSG_S_RATE_LIMIT = "RATE_LIMIT\n"; // Basic concept, fuller implementation if needed
const std::string MSG_S_SESSION_KEY_PREFIX = "SKEY:";
const std::string MSG_S_HEADER_ACK = "HDR_ACK\n";
const std::string MSG_S_HEADER_NACK = "HDR_NACK\n";
const std::string MSG_S_TRANSFER_SUCCESS = "TRANSFER_SUCCESS\n";
const std::string MSG_S_TRANSFER_FAIL_CHECKSUM = "TRANSFER_FAIL_CHECKSUM\n";
const std::string MSG_S_TRANSFER_FAIL_OTHER = "TRANSFER_FAIL_OTHER\n";

const int DEFAULT_PORT = 8080;
const int BUFFER_SIZE = 4096;
const std::string RECEIVED_FILES_DIR = "received_files"; // Relative to server executable

// For PIN "hashing" and session key encryption
const std::string PIN_SALT = "some_cpp_salt_";
const int SESSION_KEY_LENGTH = 16; // bytes

#endif // PROTOCOL_H