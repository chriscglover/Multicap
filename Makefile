# Makefile for multicap - High-performance multicast capture utility

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -march=native -pthread
LDFLAGS = -pthread

# Debug build flags
DEBUG_CFLAGS = -Wall -Wextra -g -O0 -pthread -DDEBUG

TARGET = multicap
SRC = multicap.c
OBJ = $(SRC:.c=.o)
MANPAGE = multicap.1

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man/man1

.PHONY: all clean install uninstall debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: $(TARGET)

# Static build (for portability)
static: $(SRC)
	$(CC) $(CFLAGS) -static -o $(TARGET) $< $(LDFLAGS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/
	@echo "Installed to $(DESTDIR)$(BINDIR)/$(TARGET)"
	@echo "Man page installed to $(DESTDIR)$(MANDIR)/$(MANPAGE)"
	@echo ""
	@echo "Note: For optimal performance, consider:"
	@echo "  1. Running as root for SO_BINDTODEVICE and real-time scheduling"
	@echo "  2. Setting capabilities: sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep $(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/$(MANPAGE)

clean:
	rm -f $(TARGET) $(OBJ)

# Performance tuning helper
tune:
	@echo "System tuning recommendations for high-bitrate capture:"
	@echo ""
	@echo "1. Increase socket buffer sizes:"
	@echo "   sudo sysctl -w net.core.rmem_max=536870912"
	@echo "   sudo sysctl -w net.core.rmem_default=67108864"
	@echo ""
	@echo "2. Increase network interface ring buffer:"
	@echo "   sudo ethtool -G eth0 rx 4096"
	@echo ""
	@echo "3. Enable receive packet steering (RSS):"
	@echo "   echo 'ffffffff' | sudo tee /sys/class/net/eth0/queues/rx-0/rps_cpus"
	@echo ""
	@echo "4. Disable interrupt coalescing for lower latency:"
	@echo "   sudo ethtool -C eth0 rx-usecs 0"
	@echo ""
	@echo "5. Use NUMA-aware allocation (if applicable):"
	@echo "   numactl --cpunodebind=0 --membind=0 ./multicap ..."

help:
	@echo "multicap Makefile targets:"
	@echo "  all      - Build optimized release binary (default)"
	@echo "  debug    - Build debug binary with symbols"
	@echo "  static   - Build statically linked binary"
	@echo "  install  - Install to $(BINDIR)"
	@echo "  uninstall- Remove from $(BINDIR)"
	@echo "  clean    - Remove build artifacts"
	@echo "  tune     - Show system tuning recommendations"
	@echo "  help     - Show this message"
