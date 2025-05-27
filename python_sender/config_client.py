# python_client/config_client.py
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080 # Must match C++ server's DEFAULT_PORT
BUFFER_SIZE = 4096
PIN_SALT_PY = "some_cpp_salt_" # Must match C++ server's PIN_SALT for deriving key for SKEY
SESSION_KEY_LENGTH_PY = 16 # Must match C++ server