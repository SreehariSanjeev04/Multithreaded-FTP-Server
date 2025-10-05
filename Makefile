CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LDFLAGS = -lstdc++fs -lpthread -lbcrypt

TARGET = ftp_server
SOURCES = ftp_server.cpp

all: $(TARGET)

$(TARGET):$(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean