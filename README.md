# Secure File Transfer (C++ Server (Receiver) & Python Client (Sender) - Simplified XOR)

This project demonstrates a file transfer application with a C++ server and a Python client. It uses XOR encryption for basic confidentiality and a simple checksum for integrity. The focus is on illustrating C++ and Python interoperability in a client-server model with simplified security mechanisms.

## Features

* **C++ Server**: Multi-threaded, handles client connections, PIN authentication, XOR-based session key exchange, receives files, decrypts with XOR, and verifies a simple checksum.
* **Python Client**: Connects to the C++ server, authenticates using a PIN, sends a file encrypted with XOR, and displays transfer progress.
* **Simple Encryption**: XOR encryption for session key exchange and file content.
* **Simple Integrity Check**: Sum-of-bytes checksum.
* **Basic Logging**: Both client and server print log messages to the console.

## Project Structure
secure_file_transfer_cpp_py/
* ├── cpp_server/
* │   ├── main.cpp
* │   ├── security_ops.h
* │   ├── security_ops.cpp
* │   ├── protocol.h
* │   └── Makefile
* ├── python_client/
* │   ├── client.py
* │   ├── security_ops_py.py
* │   └── config_client.py
* ├── received_files/       # Created by C++ server
* └── README.md

## Prerequisites

* **C++ Server**:
    * A C++ compiler supporting C++17 (for `filesystem`).
    * `make` utility.
    * Standard libraries (iostream, string, vector, thread, fstream, sys/socket, etc.).
* **Python Client**:
    * Python 3.6+
    * Supports Only Linux Terminals

## Setup and Usage

1.  **Compile the C++ Server**:
    Navigate to the `cpp_reciever` directory:
    ```bash
    cd cpp_reciever
    make
    ```
    This will create an executable named `cpp_server`.

2.  **Run the C++ Server**:
    From the `cpp_reciever` directory:
    ```bash
    ./cpp_server
    ```
    The server will start listening on port 8080 (by default, see `protocol.h`). It will create a `received_files` directory if it doesn't exist.

3.  **Configure the Python Client (Optional)**:
    Edit `python_client/config_client.py` if the server IP or port differs from the defaults (`127.0.0.1`, `8080`). Ensure `PIN_SALT_PY` and `SESSION_KEY_LENGTH_PY` match the C++ server's `PIN_SALT` and `SESSION_KEY_LENGTH` from `protocol.h`.

4.  **Run the Python Client**:
    Open another terminal and navigate to the `python_client` directory.
    ```bash
    cd ../python_sender # If you were in cpp_server
    python client.py <path_to_file_to_send> <pin>
    ```
    * `<path_to_file_to_send>`: The full path to the file you want to send.
    * `<pin>`: The PIN the server expects (default is "1234" in `cpp_server/main.cpp`).

    **Example**:
    ```bash
    python client.py /path/to/your/document.txt 1234
    ```

## Important Notes

* **Security**: The security mechanisms (PIN "hashing", XOR encryption, simple checksum) are for **demonstration purposes only** and are **NOT cryptographically secure** for protecting sensitive data in real-world applications.
* **Error Handling**: Basic error handling is implemented. More robust error checking and recovery would be needed for a production system.
* **Compatibility**: The PIN derivation logic and checksum calculation logic **must be identical** between the C++ server and Python client for successful operation.
* **Path for received_files**: The C++ server creates `received_files` relative to its execution directory.
