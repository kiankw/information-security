C := gcc
GMP := -lgmp
INC_DIR := include
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
INCLUDE := -I./$(INC_DIR)

$(BIN_DIR)/main : $(BUILD_DIR)/main.o $(BUILD_DIR)/str.o $(BUILD_DIR)/key.o $(BUILD_DIR)/int_and_str.o $(BUILD_DIR)/encrypt.o $(BUILD_DIR)/decrypt.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(INCLUDE) $^ -o $@ $(GMP)

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(INCLUDE) -c $^ -o $@ $(GMP)

clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf $(BIN_DIR)
