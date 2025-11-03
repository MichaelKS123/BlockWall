# Blockwall Network IDS Makefile
# Author: Michael Semera

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -pthread
INCLUDES = -I.

# Target executable
TARGET = blockwall

# Source files
MAIN_SRC = main.cpp

# Header files
HEADERS = blockwall.h

# Default target
all: $(TARGET)

# Build main application
$(TARGET): $(MAIN_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(MAIN_SRC) -o $(TARGET)
	@echo "✓ Blockwall IDS built successfully"

# Clean build artifacts
clean:
	rm -f $(TARGET)
	rm -f *.o
	rm -f blockwall_report_*.txt
	@echo "✓ Build artifacts cleaned"

# Run the application
run: $(TARGET)
	@echo "Starting Blockwall IDS..."
	@./$(TARGET)

# Install to system
install: $(TARGET)
	@echo "Installing Blockwall IDS..."
	@sudo cp $(TARGET) /usr/local/bin/
	@echo "✓ Installed to /usr/local/bin/"

# Uninstall from system
uninstall:
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "✓ Uninstalled from /usr/local/bin/"

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean $(TARGET)
	@echo "✓ Debug build completed"

# Help target
help:
	@echo "Blockwall Network IDS Build System"
	@echo "Author: Michael Semera"
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Build Blockwall IDS"
	@echo "  make run          - Build and run"
	@echo "  make debug        - Build with debug symbols"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make install      - Install to system"
	@echo "  make uninstall    - Remove from system"
	@echo "  make help         - Show this help message"

.PHONY: all clean run install uninstall debug help