 # @file Makefile
 # @author Martin Kostelník (xkoste12@stud.fit.vutbr.cz)
 # @brief IPK - Project 2 - Packet sniffer Makefile
 # @version 1.0
 # @date 2020-05-03

CXX = g++
EXECUTABLE = proj2
OBJS = main.o

LDFLAGS = -lpcap

.PHONY: all clean pack

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CXX) main.cpp -o $(EXECUTABLE) $(LDFLAGS)
	
clean:
	rm -f $(EXECUTABLE) *.o *.out xkoste12.tar

pack:
	tar -cvf xkoste12.tar main.cpp Makefile manual.pdf README.md
