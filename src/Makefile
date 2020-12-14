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


# Targets	                                                       
DAEMON			?=  bledaemon
UTIL 			?=  bletool
LIBRARIES 		?=  libglbleapi.so

# Flags		                                                       
CC	 			:=  gcc
CFLAG			:=  -g -Wall

# Directories and files
DAEMON_INCDIRS	:= 	daemon/bledriver/silabs \
					daemon/bledriver/util	\
					daemon/bledriver/util/uart \
					daemon/bledriver/util/hal \
					components/dev_mgr \
					components/log \
					include/

DAEMON_SRCDIRS	:=  daemon  \
					daemon/bledriver/util/hal  \
					daemon/bledriver/util/uart  \
					daemon/bledriver/silabs  \
					components/dev_mgr  \
					components/log	

LIB_INCDIRS		:= 	lib \
					components/dev_mgr \
					components/log \
					include

LIB_SRCDIRS		:=  lib  \
					components/dev_mgr \
					components/log	

UTIL_INCDIRS	:= 	lib \
					tool \
					components/dev_mgr \
					components/log	\
					include

UTIL_SRCDIRS	:=  lib  \
					tool \
					components/dev_mgr  \
					components/log	

# Objects directories 
DAEMON_DIR 		=	daemonbuild
UTIL_DIR 		=	utilbuild
LIB_DIR 		=	libbuild
EXE_DIR 		=	exe

NULLDEVICE := /dev/null
$(shell mkdir $(DAEMON_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(UTIL_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(LIB_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(EXE_DIR)>$(NULLDEVICE) 2>&1)

# Rules
DAEMON_INCLUD 	:=  $(patsubst %, -I %, $(DAEMON_INCDIRS))
LIB_INCLUD	 	:=  $(patsubst %, -I %, $(LIB_INCDIRS))		
UTIL_INCLUD 	:=  $(patsubst %, -I %, $(UTIL_INCDIRS))	

DAEMON_CFILES	:=  $(foreach dir, $(DAEMON_SRCDIRS), $(wildcard $(dir)/*.c))
UTIL_CFILES		:=  $(foreach dir, $(UTIL_SRCDIRS), $(wildcard $(dir)/*.c))
LIB_CFILES		:=  $(foreach dir, $(LIB_SRCDIRS), $(wildcard $(dir)/*.c))
$(info DAEMON_CFILES = $(DAEMON_CFILES))

DAEMON_OBJS 	:=  $(patsubst %.c, $(DAEMON_DIR)/%.o, $(notdir $(DAEMON_CFILES)))
UTIL_OBJS	 	:=  $(patsubst %.c, $(UTIL_DIR)/%.o, $(notdir $(UTIL_CFILES)))
LIB_OBJS	 	:=  $(patsubst %.c, $(LIB_DIR)/%.o, $(notdir $(LIB_CFILES)))
$(info DAEMON_OBJS = $(DAEMON_OBJS))

VPATH			:= 	$(DAEMON_SRCDIRS)  $(UTIL_SRCDIRS)  $(LIB_SRCDIRS)

# Dependences               
DAEMON_DEPENDS	:=  -lubox -lubus -ljson-c -lblobmsg_json -lglutil
UTIL_DEPENDS 	+=  -lubox -lubus -ljson-c -lblobmsg_json
LIB_DEPENDS 	+=  -lubox -lubus -ljson-c -lblobmsg_json

all:	$(EXE_DIR)/$(DAEMON) $(EXE_DIR)/$(UTIL) $(EXE_DIR)/$(LIBRARIES)

# Create bledaemon
$(DAEMON_DIR)/%.o : %.c
	@echo "Building file: $<"
	$(CC) -c $(CFLAG) $(DAEMON_INCLUD) ${DAEMON_DEPENDS}  $< -o $@ 

$(EXE_DIR)/$(DAEMON): $(DAEMON_OBJS)
	@echo "Linking target: $@"
	$(CC) $^ -o $@ $(DAEMON_DEPENDS)

# Create shared lib
$(LIB_DIR)/%.o : %.c
	@echo "Building file: $<"
	$(CC) -c $(CFLAG) $(LIB_INCLUD) ${LIB_DEPENDS} -fPIC $< -o $@ 

$(EXE_DIR)/$(LIBRARIES): $(LIB_OBJS)
	@echo "Linking target: $@"
	$(CC) $^ -o $@ $(LIBFLAGS) $(CFLAG)  -shared $(LIBDEPENDS)

# Create util tool
$(UTIL_DIR)/%.o : %.c
	@echo "Building file: $<"
	$(CC) -c $(CFLAG) ${UTIL_INCLUD}  $(UTIL_DEPENDS) $< -o $@ 

$(EXE_DIR)/$(UTIL): $(UTIL_OBJS)
	@echo "Linking target: $@"
	$(CC) $^ -o $@ $(UTIL_DEPENDS)	

.PHONY: clean
clean:
	rm -rf $(DAEMON_DIR) $(UTIL_DIR) $(LIB_DIR) $(EXE_DIR)