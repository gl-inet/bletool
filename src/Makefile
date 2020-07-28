 ###################################################################
 # Copyright 2020 GL-iNet. https://www.gl-inet.com/
 # 
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 # http://www.apache.org/licenses/LICENSE-2.0
 # 
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 ####################################################################

.PHONY: all clean

####################################################################
# Definitions                                                      #
####################################################################

DAEMON = bledaemon
UTIL = bletool
LIBRARIES = libglbleapi.so

DAEMON_DIR = daemonbuild
UTIL_DIR = utilbuild
LIB_DIR = libbuild
EXE_DIR = exe


####################################################################
# Definitions of toolchain.                                        #
# You might need to do changes to match your system setup          #
####################################################################

NULLDEVICE := /dev/null

# Create directories and do a clean which is compatible with parallell make
$(shell mkdir $(DAEMON_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(UTIL_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(LIB_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(EXE_DIR)>$(NULLDEVICE) 2>&1)

CC = gcc
LD = gcc


####################################################################
# Flags                                                            #
####################################################################

INCLUDEPATHS += \
-I bledriver/silabs \
-I uart


DEBUG += \
-g \
-O0 \
-w

override CFLAGS += \
-c \
-std=gnu99 \
$(DEBUG)

# NOTE: The -Wl,--gc-sections flag may interfere with debugging using gdb.
override LDFLAGS += 

####################################################################
# Files                                                            #
####################################################################

DAEMON_SRC +=  \
daemon.c \
hal.c \
bledriver/silabs/silabs_bleapi.c \
uart/uart.c

UTIL_SRC += \
cli.c \
libglbleapi.c

LIB_SRC += \
libglbleapi.c

DAEMONDEPENDS += -lubox -lubus -ljson-c -lblobmsg_json -luci 
UTILDEPENDS += -lubox -lubus -ljson-c -lblobmsg_json
LIBDEPENDS += -lubox -lubus -ljson-c -lblobmsg_json


####################################################################
# Rules                                                            #
####################################################################

DAEMON_FILES = $(notdir $(DAEMON_SRC) )
DAEMON_OBJS = $(addprefix $(DAEMON_DIR)/, $(DAEMON_FILES:.c=.o))
UTIL_FILES = $(notdir $(UTIL_SRC) )
UTIL_OBJS = $(addprefix $(UTIL_DIR)/, $(UTIL_FILES:.c=.o))
LIB_FILES = $(notdir $(LIB_SRC) )
LIB_OBJS = $(addprefix $(LIB_DIR)/, $(LIB_FILES:.c=.o))
VPATH = bledriver:uart:bledriver/silabs

# Default build is debug build
all:    $(EXE_DIR)/$(DAEMON) $(EXE_DIR)/$(UTIL) $(EXE_DIR)/$(LIBRARIES)

# Create objects from C SRC files
$(DAEMON_DIR)/%.o: %.c
	@echo "Building file: $<"
	$(CC) $(CFLAGS) $(INCLUDEPATHS) -c $< -o $@

# Create ble DAEMON
$(EXE_DIR)/$(DAEMON): $(DAEMON_OBJS)
	@echo "Linking target: $@"
	$(CC) $(LDFLAGS) $^ -o $@ $(DAEMONDEPENDS)

# Create objects from C SRC files
$(LIB_DIR)/%.o: %.c
	@echo "Building file: $<"
	$(CC) $(CFLAGS) $(INCLUDEPATHS) -fPIC -c $< -o $@

# Create shared lib
$(EXE_DIR)/$(LIBRARIES): $(LIB_OBJS)
	@echo "Linking target: $@"
	$(CC) $^ -o $@ $(LIBFLAGS) -shared $(LIBDEPENDS)

# Create objects from C SRC files
$(UTIL_DIR)/%.o: %.c
	@echo "Building file: $<"
	$(CC) $(CFLAGS) $(INCLUDEPATHS) -c $< -o $@

# Create util tool
$(EXE_DIR)/$(UTIL): $(UTIL_OBJS)
	@echo "Linking target: $@"
	$(CC) $^ -o $@  $(UTILDEPENDS)



clean:
	rm -rf $(DAEMON_DIR) $(UTIL_DIR) $(LIB_DIR) $(EXE_DIR)