C := gcc
INC_DIR := include
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
INCLUDE := -I./$(INC_DIR)

$(BIN_DIR)/main : $(BUILD_DIR)/main.o $(BUILD_DIR)/md5.o $(BUILD_DIR)/hmac-md5.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(INCLUDE) $^ -o $@

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(INCLUDE) -c $^ -o $@

clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf $(BIN_DIR)
