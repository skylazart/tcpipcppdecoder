CXX=g++
CXXFLAGS=-Wall -O2 -g -std=c++11
BIN=challenge

SRC=$(wildcard *.cpp)
INC=$(wildcard *.hpp)
OBJ=$(SRC:.cpp=.o)

LIBS=-lpcap

all: challenge
	$(CXX) $(CXXFLAGS) -o $(BIN) $(OBJ) $(LIBS)

challenge: $(OBJ) $(INC)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^

clean:
	rm -rf *.o
	rm -rf $(BIN)
