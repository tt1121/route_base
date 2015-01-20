msg_server: msg_server.o
	$(CC) $(LDFLAGS) msg_server.o -o msg_server $(LIBS)
msg_server.o:msg_server.c
	$(CC) $(CFLAGS) -c msg_server.c -o msg_server.o $(INS)
clean:
	rm -rf *.o msg_server
