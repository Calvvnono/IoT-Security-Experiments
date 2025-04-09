# Compiler and flags
CXX = g++
# Correct include path pointing to the 'pbc' subdirectory
CXXFLAGS = -std=c++17 -Wall -Wextra -g -I/usr/local/include/pbc

# Linker flags and libraries
# Library path is still correct
LDFLAGS = -L/usr/local/lib
LIBS = -lgmp -lpbc -lcrypto # Link against GMP, PBC, and OpenSSL crypto

# Source file and executable name - Double check your actual filename case
# Assuming kp_abe.cpp based on previous attempt, adjust if it's KP_ABE.cpp
SRC = KP-ABE.cpp
EXEC = kp-abe

# Default target
all: $(EXEC)

# Rule to build the executable
$(EXEC): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(EXEC) $(SRC) $(LDFLAGS) $(LIBS)

# Clean up target
clean:
	rm -f $(EXEC)

# Phony targets
.PHONY: all clean