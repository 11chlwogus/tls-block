all:
	g++ -O2 -o tls-block tls_block.cpp -lpcap

clean:
	rm -f tls-block *.o
