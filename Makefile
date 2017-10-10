all: send_arp

send_arp : send_arp.o main.o
	g++ -o send_arp send_arp.o main.o -lpcap

send_arp.o: send_arp.c send_arp.h
	g++ -c -o send_arp.o send_arp.cpp -lpcap

main.o: main.c send_arp.h
	g++ -c -o main.o main.cpp

clean:
	rm -f send_arp
	rm -f *.o