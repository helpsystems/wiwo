
all: worker workermon

workermon: monitor.o system.o mac.o
	$(CC) monitor.o system.o mac.o $(LDFLAGS) -Wall -lpcap -o $@

monitor.o: monitor.c
	$(CC) monitor.c $(CFLAGS) -Wall -c

worker: wiwo.o mac.o wireless.o system.o
	$(CC) wiwo.o system.o mac.o wireless.o $(LDFLAGS) -Wall -lpcap -o $@

wiwo.o: wiwo.c
	$(CC) wiwo.c $(CFLAGS) -Wall -c

system.o: system.c
	$(CC) system.c $(CFLAGS) -Wall -c

wireless.o: wireless.c
	$(CC) wireless.c $(CFLAGS) -Wall -c

mac.o: mac.c
	$(CC) mac.c $(CFLAGS) -Wall -c

clean:
	rm -f *.o worker workermon
