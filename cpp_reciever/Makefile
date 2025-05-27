CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread
LDFLAGS =
SOURCES = main.cpp security_ops.cpp
EXECUTABLE = cpp_server

all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES) security_ops.h protocol.h
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(EXECUTABLE) $(LDFLAGS) -lstdc++fs

clean:
	rm -f $(EXECUTABLE) *.o