
output: main.o
	gcc -fopenmp main.o -o output -lssl -lcrypto

main.o: main.c
	gcc -fopenmp -c main.c -lssl -lcrypto

clean:
	rm *.o output

run:
	./output