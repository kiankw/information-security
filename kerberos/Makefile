C := gcc
INC_DIR := include
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
PIP_DIR := pip

INCLUDE := -I./$(INC_DIR)
PTHREAD := -pthread

all:$(BIN_DIR)/as $(BIN_DIR)/ss $(BIN_DIR)/tgs $(BIN_DIR)/client

$(BIN_DIR)/client : $(BUILD_DIR)/client.o $(BUILD_DIR)/md5.o $(BUILD_DIR)/encrypt_decrypt.o $(BUILD_DIR)/des.o
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(PIP_DIR)
	$(CC) $(PTHREAD) $(INCLUDE) $^ -o $@

$(BIN_DIR)/as : $(BUILD_DIR)/as.o $(BUILD_DIR)/md5.o $(BUILD_DIR)/encrypt_decrypt.o $(BUILD_DIR)/des.o
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(PIP_DIR)
	$(CC) $(PTHREAD) $(INCLUDE) $^ -o $@

$(BIN_DIR)/ss : $(BUILD_DIR)/ss.o $(BUILD_DIR)/md5.o $(BUILD_DIR)/encrypt_decrypt.o $(BUILD_DIR)/des.o
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(PIP_DIR)
	$(CC) $(PTHREAD) $(INCLUDE) $^ -o $@

$(BIN_DIR)/tgs : $(BUILD_DIR)/tgs.o $(BUILD_DIR)/md5.o $(BUILD_DIR)/encrypt_decrypt.o $(BUILD_DIR)/des.o
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(PIP_DIR)
	$(CC) $(PTHREAD) $(INCLUDE) $^ -o $@

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(PTHREAD) $(INCLUDE) -c $^ -o $@

clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf $(BIN_DIR)
	@rm -rf $(PIP_DIR)
