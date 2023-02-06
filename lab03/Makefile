CC          = g++
LD          = g++ 
CFLAG       = -Wall
PROG_NAME1   = myclient
PROG_NAME2   = myserver

SRC_DIR     = ./src
BUILD_DIR   = ./build
BIN_DIR     = ./bin

SRC_LIST1 = ./src/myclient.cpp
OBJ_LIST1 = $(BUILD_DIR)/$(notdir $(SRC_LIST1:.cpp=.o))

SRC_LIST2 = ./src/myserver.cpp
OBJ_LIST2 = $(BUILD_DIR)/$(notdir $(SRC_LIST2:.cpp=.o))

.PHONY: all clean $(PROG_NAME1) client_compile $(PROG_NAME2) server_compile

all: $(PROG_NAME1) $(PROG_NAME2)

client_compile: 
	$(CC) -c $(CFLAG) $(SRC_LIST1) -o $(OBJ_LIST1)

$(PROG_NAME1): client_compile
	$(LD) $(OBJ_LIST1) -o $(BIN_DIR)/$@

server_compile: 
	$(CC) -c $(CFLAG) $(SRC_LIST2) -o $(OBJ_LIST2)

$(PROG_NAME2): server_compile
	$(LD) $(OBJ_LIST2) -o $(BIN_DIR)/$@

clean:
	rm -f $(BIN_DIR)/$(PROG_NAME1) $(BUILD_DIR)/*.o
	rm -f $(BIN_DIR)/$(PROG_NAME2) $(BUILD_DIR)/*.o