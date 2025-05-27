# python_client/client.py
import socket
import os
import sys
import time
from config_client import SERVER_IP, SERVER_PORT, BUFFER_SIZE, PIN_SALT_PY, SESSION_KEY_LENGTH_PY
from security_ops_py import (
    derive_key_from_pin_py,
    xor_encrypt_decrypt_py,
    bytes_to_hex_py,
    hex_to_bytes_py,
    calculate_checksum_py
)

def log_message_client(message):
    print(f"[CLIENT LOG] {time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")

def send_with_newline(sock, message_str):
    sock.sendall((message_str + "\n").encode('utf-8'))

def recv_line(sock):
    data = b""
    while True:
        chunk = sock.recv(1)
        if not chunk or chunk == b'\n':
            break
        data += chunk
    return data.decode('utf-8')


def send_file_to_cpp_server(file_path, pin):
    if not os.path.exists(file_path):
        log_message_client(f"Error: File not found at '{file_path}'")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        log_message_client(f"Connecting to C++ server at {SERVER_IP}:{SERVER_PORT}...")
        client_socket.connect((SERVER_IP, SERVER_PORT))
        log_message_client("Connected.")

        # 1. Send PIN
        send_with_newline(client_socket, f"PIN:{pin}")
        auth_response = recv_line(client_socket)
        log_message_client(f"Server Auth Response: {auth_response}")

        if auth_response != "AUTH_SUCCESS":
            log_message_client(f"Authentication failed or server busy: {auth_response}")
            return

        # 2. Receive Session Key
        skey_response = recv_line(client_socket)
        if not skey_response.startswith("SKEY:"):
            log_message_client(f"Error: Invalid session key response: {skey_response}")
            return
        
        skey_encrypted_hex = skey_response[len("SKEY:"):]
        skey_encrypted_bytes = hex_to_bytes_py(skey_encrypted_hex)

        pin_derived_skey_dec_key = derive_key_from_pin_py(pin, PIN_SALT_PY, SESSION_KEY_LENGTH_PY)
        session_key_plain_bytes = xor_encrypt_decrypt_py(skey_encrypted_bytes, pin_derived_skey_dec_key)
        log_message_client(f"Session key received and decrypted (length: {len(session_key_plain_bytes)}).")


        # 3. Prepare and Send File Header
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        
        with open(file_path, 'rb') as f:
            file_content_for_checksum = f.read()
        file_checksum = calculate_checksum_py(file_content_for_checksum)

        header_str = f"FHDR:{filename}:{filesize}:{file_checksum}"
        send_with_newline(client_socket, header_str)
        log_message_client(f"Sent file header: {header_str}")

        header_ack_response = recv_line(client_socket)
        log_message_client(f"Server Header Ack Response: {header_ack_response}")
        if header_ack_response != "HDR_ACK":
            log_message_client(f"Server did not acknowledge header: {header_ack_response}")
            return

        # 4. Send File Data (chunked and XOR encrypted with session key)
        log_message_client("Starting file data transmission...")
        bytes_sent = 0
        start_time = time.time()

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                
                encrypted_chunk = xor_encrypt_decrypt_py(chunk, session_key_plain_bytes)
                client_socket.sendall(encrypted_chunk)
                bytes_sent += len(chunk) # Original chunk length for progress

                # Progress reporting
                percentage = (bytes_sent / filesize) * 100
                elapsed_time = time.time() - start_time + 1e-9
                speed_kbps = (bytes_sent / 1024) / elapsed_time
                sys.stdout.write(f"\rSending {filename}: {bytes_sent}/{filesize} bytes ({percentage:.2f}%) | Speed: {speed_kbps:.2f} KB/s  ")
                sys.stdout.flush()
        
        sys.stdout.write("\n") # New line after progress bar
        log_message_client("File data sent completely.")

        # 5. Receive Transfer Status from Server
        transfer_status_response = recv_line(client_socket)
        log_message_client(f"Server Transfer Status: {transfer_status_response}")
        if transfer_status_response == "TRANSFER_SUCCESS":
            print("File transferred successfully and verified by server.")
        else:
            print(f"File transfer failed or verification error: {transfer_status_response}")

    except ConnectionRefusedError:
        log_message_client(f"Connection refused. Is the C++ server running at {SERVER_IP}:{SERVER_PORT}?")
    except Exception as e:
        log_message_client(f"An error occurred: {e}")
    finally:
        log_message_client("Closing connection.")
        client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <file_path> <pin>")
        sys.exit(1)
    
    file_to_send = sys.argv[1]
    user_pin = sys.argv[2]
    send_file_to_cpp_server(file_to_send, user_pin)