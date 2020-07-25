all: pcap-test

pcap-test: main.o extractor.o
	g++ -o pcap-test main.o extractor.o -lpcap

main.o: extractor.h main.cpp
	g++ -c -o main.o main.cpp

extractor.o: extractor.h extractor.cpp
	g++ -c -o extractor.o extractor.cpp

clean:
	rm -f pcap-test *.o

