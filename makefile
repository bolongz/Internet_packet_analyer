all: analyzer
CC = g++ -std=c++11  -Wall

analyzer: analyzer.cpp
	$(CC) -o analyzer analyzer.cpp
clean:
	rm analyzer
