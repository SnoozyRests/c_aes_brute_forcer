
output: main.o
	mpicc main.o -o output -lssl -lcrypto

main.o: main.c
	gcc -fopenmp -c main.c -lssl -lcrypto

clean:
	rm *.o output

test:
	mpirun -np 62 output

run:
	mpirun -np 4 output
