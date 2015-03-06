MSGSERVER = msg_server

SOURCES = imove_msg_server.c imove_queue.c imove_log.c imove_api_func.c
#MSGSERVER_FILES = imove_msg_server.c
#MSGSERVER_FILES += imove_queue.c imove_log.c imove_api_func.c

SRC_UPGRADE_PATH = ./fw_upgrade
SOURCES += $(wildcard $(SRC_UPGRADE_PATH)/*.c)

TARGET = $(MSGSERVER)
OBJS = $(SOURCES:.c=.o)

all: $(TARGET)
$(MSGSERVER) : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(MSGSERVER) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *.o $(TARGET)
