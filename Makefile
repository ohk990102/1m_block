CXXFLAGS =
LDLIBS = -lnetfilter_queue
TARGET = 1m_block

all: $(TARGET)

debug: CXXFLAGS += -DDEBUG -g
debug: $(TARGET)

clean:
	rm -f $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) -o $@ $< $(LDLIBS) $(CXXFLAGS)