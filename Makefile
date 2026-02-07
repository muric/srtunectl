# Variables
APP_NAME := srtunectl
SYSTEMD_DIR := /etc/systemd/system
NETWORK_DIR := /etc/systemd/network
SERVICE_NAME := route.service
IPROUTE_CONF := iproute.conf
IPROUTE_GIT_DIR := $(shell pwd)

# Default target
all: build

# Build target
build:
	@echo "Building the application..."
	go build -o ./output/${APP_NAME} .

# Clean target
clean:
	@echo "Cleaning up..."
	rm -rf ./output/${APP_NAME}
	rm -f /usr/bin/${APP_NAME}

	# Remove network file if interface is defined
	@if [ -f "$(IPROUTE_CONF)" ]; then \
		INTERFACE=$$(grep '^interface=' $(IPROUTE_CONF) | cut -d'=' -f2); \
		if [ -n "$$INTERFACE" ]; then \
			rm -f $(NETWORK_DIR)/99-$$INTERFACE.network; \
			echo "Removed network file $(NETWORK_DIR)/99-$$INTERFACE.network"; \
		fi; \
	fi

# Install application, systemd service, and network file
install: build
	# Install binary
	install -m 0755 ./output/${APP_NAME} /usr/bin/$(APP_NAME)

	# Install systemd service
	install -d $(SYSTEMD_DIR)
	sed -e 's|@IPROUTE_GIT_DIR@|$(IPROUTE_GIT_DIR)|g' \
		route.service.in \
		> $(SYSTEMD_DIR)/$(SERVICE_NAME)

	systemctl daemon-reload
	systemctl enable $(SERVICE_NAME)

	# Generate network file
	@if [ ! -f "$(IPROUTE_CONF)" ]; then \
		echo "ERROR: $(IPROUTE_CONF) not found"; \
		exit 1; \
	fi
	INTERFACE=$$(grep '^interface=' $(IPROUTE_CONF) | cut -d'=' -f2); \
	if [ -z "$$INTERFACE" ]; then \
		echo "ERROR: interface not found in $(IPROUTE_CONF)"; \
		exit 1; \
	fi; \
	echo "Generating network file for interface $$INTERFACE..."; \
	mkdir -p $(NETWORK_DIR); \
	printf "%s\n" \
"[Match]" \
"Name=$$INTERFACE" \
"" \
"[Network]" \
"KeepConfiguration=yes" \
"IgnoreCarrierLoss=yes" \
"" \
"[Link]" \
"Unmanaged=yes" > $(NETWORK_DIR)/99-$$INTERFACE.network

# Declare phony targets
.PHONY: all build clean install

