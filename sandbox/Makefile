# Klear-CodeTest Sandbox Judge System Makefile
# Sandbox judge system build file

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
DEBUG_FLAGS = -g -O0 -DDEBUG

# Target files
TARGET = judge
SOURCE = judge.cpp

# Default target
.PHONY: all clean debug install help

all: $(TARGET)

# Build judge
$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(SOURCE) -o $(TARGET)

# Debug version
debug: $(SOURCE)
	$(CXX) $(CXXFLAGS) $(DEBUG_FLAGS) $(SOURCE) -o $(TARGET)

# Clean
clean:
	rm -f $(TARGET)

# Install
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)

# Help
help:
	@echo "Available targets:"
	@echo "  all      - Build judge (default)"
	@echo "  debug    - Build debug version"
	@echo "  clean    - Clean executable"
	@echo "  install  - Install to system"
	@echo "  help     - Show this help" 