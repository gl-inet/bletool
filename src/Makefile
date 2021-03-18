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
PROJECT			?=  bledemo

# Flags		                                                       
CC	 			:=  gcc
CFLAG			:=  -g -Wall

# Directories and files
DAEMON_INCDIRS	:= 	daemon/bledriver/silabs \
					daemon/bledriver/util	\
					components/dev_mgr \
					components/log \
					components/thread \
					components/timestamp \
					include

DAEMON_SRCDIRS	:=  daemon  \
					daemon/bledriver/util	\
					daemon/bledriver/silabs  \
					components/dev_mgr  \
					components/log  \
					components/timestamp \
					components/thread

LIB_INCDIRS		:= 	lib \
					components/dev_mgr \
					components/log \
					components/thread \
					components/timestamp \
					include \
					daemon/bledriver/util						

LIB_SRCDIRS		:=  lib  \
					components/dev_mgr \
					components/log	\
					components/thread \
					components/timestamp \
					daemon/bledriver/util					

UTIL_INCDIRS	:= 	lib \
					tool \
					components/dev_mgr \
					components/log	\
					include \
					daemon/bledriver/util

UTIL_SRCDIRS	:=  lib  \
					tool \
					components/dev_mgr  \
					components/log	\
					daemon/bledriver/util
					
PROJECT_INCDIRS	:=  lib  \
					project \
					include \
					components/thread \
					components/dev_mgr \
					components/log	\
					daemon/bledriver/util

PROJECT_SRCDIRS	:=  lib  \
					project \
					components/thread \
					components/dev_mgr  \
					components/log	\
					daemon/bledriver/util

# Objects directories 
DAEMON_DIR 		=	daemonbuild
UTIL_DIR 		=	utilbuild
LIB_DIR 		=	libbuild
PROJECT_DIR		=	projectbuild
EXE_DIR 		=	exe

NULLDEVICE := /dev/null
$(shell mkdir $(DAEMON_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(UTIL_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(LIB_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(PROJECT_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(EXE_DIR)>$(NULLDEVICE) 2>&1)

# Rules
DAEMON_INCLUD 	:=  $(patsubst %, -I %, $(DAEMON_INCDIRS))
LIB_INCLUD	 	:=  $(patsubst %, -I %, $(LIB_INCDIRS))		
UTIL_INCLUD 	:=  $(patsubst %, -I %, $(UTIL_INCDIRS))	
PROJECT_INCLID	:=  $(patsubst %, -I %, $(PROJECT_INCDIRS))

DAEMON_CFILES	:=  $(foreach dir, $(DAEMON_SRCDIRS), $(wildcard $(dir)/*.c))
UTIL_CFILES		:=  $(foreach dir, $(UTIL_SRCDIRS), $(wildcard $(dir)/*.c))
LIB_CFILES		:=  $(foreach dir, $(LIB_SRCDIRS), $(wildcard $(dir)/*.c))
PROJECT_CFILES	:=  $(foreach dir, $(PROJECT_SRCDIRS), $(wildcard $(dir)/*.c))
$(info DAEMON_CFILES = $(DAEMON_CFILES))

DAEMON_OBJS 	:=  $(patsubst %.c, $(DAEMON_DIR)/%.o, $(notdir $(DAEMON_CFILES)))
UTIL_OBJS	 	:=  $(patsubst %.c, $(UTIL_DIR)/%.o, $(notdir $(UTIL_CFILES)))
LIB_OBJS	 	:=  $(patsubst %.c, $(LIB_DIR)/%.o, $(notdir $(LIB_CFILES)))
PROJECT_OBJS	:=  $(patsubst %.c, $(PROJECT_DIR)/%.o, $(notdir $(PROJECT_CFILES)))
$(info DAEMON_OBJS = $(DAEMON_OBJS))

VPATH			:= 	$(DAEMON_SRCDIRS)  $(UTIL_SRCDIRS)  $(LIB_SRCDIRS)  $(PROJECT_SRCDIRS)

# Dependences               
DAEMON_DEPENDS	:=  -lubox -lubus -ljson-c -lblobmsg_json -luci -lpthread
UTIL_DEPENDS 	+=  -lubox -lubus -ljson-c -lblobmsg_json -luci
LIB_DEPENDS 	+=  -lubox -lubus -ljson-c -lblobmsg_json
PROJECT_DEPENDS +=  -lubox -lubus -ljson-c -lblobmsg_json -luci -lpthread
# UTIL_DEPENDS 	:=  -lubox -lubus -ljson-c -lblobmsg_json -luci
# LIB_DEPENDS 	:=  -lubox -lubus -ljson-c -lblobmsg_json


all:	$(EXE_DIR)/$(DAEMON) $(EXE_DIR)/$(UTIL) $(EXE_DIR)/$(LIBRARIES) $(EXE_DIR)/$(PROJECT)

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

# Create demo project
$(PROJECT_DIR)/%.o : %.c
	@echo "Project building file: $<"
	$(CC) -c $(CFLAG) ${PROJECT_INCLID}  $(PROJECT_DEPENDS) $< -o $@ 

$(EXE_DIR)/$(PROJECT): $(PROJECT_OBJS)
	@echo "Linking target: $@"
	$(CC) $^ -o $@ $(PROJECT_DEPENDS)	

.PHONY: clean
clean:
	rm -rf $(DAEMON_DIR) $(UTIL_DIR) $(LIB_DIR) $(EXE_DIR) $(PROJECT)