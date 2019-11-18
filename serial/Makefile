
output: main.o
	gcc main.o -o output -lssl -lcrypto

main.o: main.c
	gcc -c main.c -lssl -lcrypto

clean:
	rm *.o output

run:
	./output