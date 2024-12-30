CC = gcc
CFLAGS = -Wall
TARGET = proc_hollow.exe
SRC_DIR = src
# OBJ_DIR = obj
SRC = $(wildcard $(SRC_DIR)/*.c)
# OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
