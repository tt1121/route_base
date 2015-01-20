msg_client: msg_client.o
	$(CC) $(LDFLAGS) msg_client.o -o msg_client $(LIBS)
msg_client.o:msg_client.c
	$(CC) $(CFLAGS) -c msg_client.c -o msg_client.o $(INS)
clean:
	rm -rf *.o msg_client
