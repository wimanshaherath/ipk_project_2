CPP = g++
CPPFLAGS = -std=c++11

EXECUTABLE = ipk-scan

all: ipk-scan.o

ipk-scan.o:
	$(CPP) -g -o $(EXECUTABLE) $(CPPFLAGS) $(EXECUTABLE).cpp

clean:
	rm $(EXECUTABLE)