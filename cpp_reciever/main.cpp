#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <sstream>
#include <filesystem> // For creating directory
#include <cstring> // For strncmp, memset
#include <algorithm> // for std::remove
#include "protocol.h"
#include "security_ops.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> // For close, read
#include <arpa/inet.h> // For inet_ntoa, inet_pton
#include <sys/types.h>
#include <map>

using namespace std;

// --- Configuration ---
const string EXPECTED_PIN = "1234"; // Server's expected PIN
// Rate limiting (basic conceptual store per server instance)
map<string, int> client_pin_attempts;
const int MAX_PIN_ATTEMPTS = 3;

void log_message(const string& message, const string& client_ip = "") {
    time_t now = time(0);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    if (!client_ip.empty()) {
        cout << buf << " [Client " << client_ip << "] " << message << endl;
    } else {
        cout << buf << " [Server] " << message << endl;
    }
}

// Helper to read a line from socket
string read_line_from_socket(int sock_fd) {
    string line;
    char buffer[1];
    while (read(sock_fd, buffer, 1) > 0) {
        if (buffer[0] == '\n') {
            break;
        }
        line += buffer[0];
    }
    return line;
}

void send_to_socket(int sock_fd, const string& message) {
    send(sock_fd, message.c_str(), message.length(), 0);
}


void handle_client(int client_socket, string client_ip_str) {
    log_message("Accepted connection.", client_ip_str);
    //char buffer[BUFFER_SIZE];

    // --- Authentication ---
    if (client_pin_attempts[client_ip_str] >= MAX_PIN_ATTEMPTS) {
        log_message("Rate limit exceeded. Closing connection.", client_ip_str);
        send_to_socket(client_socket, MSG_S_RATE_LIMIT);
        close(client_socket);
        return;
    }

    string pin_line = read_line_from_socket(client_socket);
    if (pin_line.rfind(MSG_C_PIN_PREFIX, 0) == 0) { // Starts with prefix
        string received_pin = pin_line.substr(MSG_C_PIN_PREFIX.length());
        if (received_pin == EXPECTED_PIN) {
            send_to_socket(client_socket, MSG_S_AUTH_SUCCESS);
            log_message("PIN authenticated successfully.", client_ip_str);
            client_pin_attempts[client_ip_str] = 0; // Reset attempts on success
        } else {
            client_pin_attempts[client_ip_str]++;
            log_message("Invalid PIN received. Attempts: " + to_string(client_pin_attempts[client_ip_str]), client_ip_str);
            send_to_socket(client_socket, MSG_S_AUTH_FAIL);
            close(client_socket);
            return;
        }
    } else {
        log_message("Invalid PIN message format. Closing.", client_ip_str);
        send_to_socket(client_socket, MSG_S_AUTH_FAIL); // Generic fail for protocol error
        close(client_socket);
        return;
    }

    // --- Session Key Exchange ---
    string session_key_plain = generate_session_key(SESSION_KEY_LENGTH);
    string pin_derived_skey_enc_key = derive_key_from_pin(EXPECTED_PIN, PIN_SALT, SESSION_KEY_LENGTH);

    vector<char> skey_plain_vec(session_key_plain.begin(), session_key_plain.end());
    vector<char> skey_encrypted_vec = xor_encrypt_decrypt(skey_plain_vec, pin_derived_skey_enc_key);
    string skey_encrypted_hex = bytes_to_hex(string(skey_encrypted_vec.begin(), skey_encrypted_vec.end()));

    send_to_socket(client_socket, MSG_S_SESSION_KEY_PREFIX + skey_encrypted_hex + "\n");
    log_message("Sent encrypted session key.", client_ip_str);


    // --- File Header ---
    string header_line = read_line_from_socket(client_socket);
    if (header_line.rfind(MSG_C_FILE_HEADER_PREFIX, 0) != 0) {
        log_message("Invalid file header format. Closing.", client_ip_str);
        send_to_socket(client_socket, MSG_S_HEADER_NACK);
        close(client_socket);
        return;
    }

    string header_content = header_line.substr(MSG_C_FILE_HEADER_PREFIX.length());
    stringstream ss_header(header_content);
    string filename, filesize_str, checksum_str;
    getline(ss_header, filename, ':');
    getline(ss_header, filesize_str, ':');
    getline(ss_header, checksum_str, ':');

    long filesize;
    uint32_t expected_checksum;
    try {
        filesize = stol(filesize_str);
        expected_checksum = stoul(checksum_str);
    } catch (const exception& e) {
        log_message("Malformed file header (size/checksum). Closing. Error: " + string(e.what()), client_ip_str);
        send_to_socket(client_socket, MSG_S_HEADER_NACK);
        close(client_socket);
        return;
    }
    
    // Basic filename sanitization
    filename.erase(remove_if(filename.begin(), filename.end(), 
        [](char c) { return !(isalnum(c) || c == '.' || c == '_' || c == '-'); }), filename.end());
    if (filename.empty()) filename = "default_received_file.dat";

    filesystem::path save_path = filesystem::path(RECEIVED_FILES_DIR) / filename;
    log_message("Receiving file: " + filename + " (" + filesize_str + " bytes), Expected Checksum: " + checksum_str, client_ip_str);
    send_to_socket(client_socket, MSG_S_HEADER_ACK);

    // --- File Data Reception ---
    ofstream outfile(save_path, ios::binary);
    if (!outfile.is_open()) {
        log_message("Failed to open file for writing: " + save_path.string(), client_ip_str);
        send_to_socket(client_socket, MSG_S_TRANSFER_FAIL_OTHER);
        close(client_socket);
        return;
    }

    vector<char> file_buffer_decrypted;
    file_buffer_decrypted.reserve(filesize); // Pre-allocate for received data for checksum

    long bytes_received = 0;
    int len;
    vector<char> chunk_buffer_raw(BUFFER_SIZE);

    time_t start_time = time(nullptr);
    while (bytes_received < filesize) {
        len = recv(client_socket, chunk_buffer_raw.data(), min((long)BUFFER_SIZE, filesize - bytes_received), 0);
        if (len <= 0) {
            log_message("Socket error or client disconnected during file transfer.", client_ip_str);
            outfile.close();
            filesystem::remove(save_path); // Clean up partial file
            send_to_socket(client_socket, MSG_S_TRANSFER_FAIL_OTHER);
            close(client_socket);
            return;
        }
        
        vector<char> encrypted_chunk(chunk_buffer_raw.begin(), chunk_buffer_raw.begin() + len);
        vector<char> decrypted_chunk_vec = xor_encrypt_decrypt(encrypted_chunk, session_key_plain);
        
        outfile.write(decrypted_chunk_vec.data(), decrypted_chunk_vec.size());
        file_buffer_decrypted.insert(file_buffer_decrypted.end(), decrypted_chunk_vec.begin(), decrypted_chunk_vec.end());
        bytes_received += decrypted_chunk_vec.size();

        // Simple progress to console
        if (bytes_received % (BUFFER_SIZE * 10) == 0 || bytes_received == filesize) {
             log_message("Received " + to_string(bytes_received) + "/" + to_string(filesize) + " bytes.", client_ip_str);
        }
    }
    outfile.close();
    time_t end_time = time(nullptr);
    log_message("File data reception complete. Time: " + to_string(end_time - start_time) + "s.", client_ip_str);

    // --- Checksum Verification ---
    uint32_t calculated_checksum = calculate_checksum(file_buffer_decrypted.data(), file_buffer_decrypted.size());
    log_message("Calculated checksum: " + to_string(calculated_checksum) + ", Expected: " + ::to_string(expected_checksum), client_ip_str);

    if (calculated_checksum == expected_checksum) {
        log_message("File received successfully and checksum matches.", client_ip_str);
        send_to_socket(client_socket, MSG_S_TRANSFER_SUCCESS);
    } else {
        log_message("Checksum mismatch! File may be corrupted.", client_ip_str);
        send_to_socket(client_socket, MSG_S_TRANSFER_FAIL_CHECKSUM);
        // Optionally remove the corrupted file: filesystem::remove(save_path);
    }

    close(client_socket);
    log_message("Connection closed.", client_ip_str);
}


int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if (!filesystem::exists(RECEIVED_FILES_DIR)) {
        if (!filesystem::create_directory(RECEIVED_FILES_DIR)) {
            log_message("Error: Could not create directory " + RECEIVED_FILES_DIR);
            return 1;
        }
        log_message("Created directory: " + RECEIVED_FILES_DIR);
    }


    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    address.sin_port = htons(DEFAULT_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 5) < 0) { // Listen queue of 5
        perror("listen");
        exit(EXIT_FAILURE);
    }

    log_message("Server listening on port " + to_string(DEFAULT_PORT));
    log_message("Expected PIN for clients: " + EXPECTED_PIN);


    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue; // Continue to try accepting other connections
        }
        // Get client IP
        char client_ip_cstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip_cstr, INET_ADDRSTRLEN);
        string client_ip_str(client_ip_cstr);


        thread client_thread(handle_client, new_socket, client_ip_cstr);
        client_thread.detach(); // Detach thread to handle client independently
    }

    close(server_fd);
    return 0;
}
