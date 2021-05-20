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
UTIL 			?=  bletool
LIBRARIES 		?=  libglbleapi.so
PROJECT			?=  bledemo

# Defines
DEFINES += \
	-DENABLE_DEBUG

# Flags		                                                       
CC	 			:=  gcc
CFLAG			:=  -g -Wall $(DEFINES)

# Directories and files
LIB_INCDIRS		:= 	lib \
					model_hw_cfg \
					components/dev_mgr \
					components/log \
					components/thread \
					components/timestamp \
					include \
					daemon/bledriver/util \
					daemon/bledriver/silabs						

LIB_SRCDIRS		:=  lib  \
					components/dev_mgr \
					components/log	\
					components/thread \
					components/timestamp \
					daemon/bledriver/util \
					daemon/bledriver/silabs					

UTIL_INCDIRS	:= 	lib \
					tool \
					model_hw_cfg \
					components/dev_mgr \
					components/log	\
					components/thread \
					components/timestamp \
					include \
					daemon/bledriver/util \
					daemon/bledriver/silabs

UTIL_SRCDIRS	:=  lib  \
					tool \
					components/dev_mgr  \
					components/log	\
					components/thread \
					components/timestamp \
					daemon/bledriver/util \
					daemon/bledriver/silabs
					
# PROJECT_INCDIRS	:=  lib  \
# 					project \
# 					include \
# 					components/thread \
# 					components/dev_mgr \
# 					components/log	\
# 					daemon/bledriver/util

# PROJECT_SRCDIRS	:=  lib  \
# 					project \
# 					components/thread \
# 					components/dev_mgr  \
# 					components/log	\
# 					daemon/bledriver/util

# Objects directories 
UTIL_DIR 		=	utilbuild
LIB_DIR 		=	libbuild
# PROJECT_DIR		=	projectbuild
EXE_DIR 		=	exe

NULLDEVICE := /dev/null
$(shell mkdir $(UTIL_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(LIB_DIR)>$(NULLDEVICE) 2>&1)
# $(shell mkdir $(PROJECT_DIR)>$(NULLDEVICE) 2>&1)
$(shell mkdir $(EXE_DIR)>$(NULLDEVICE) 2>&1)

# Rules
LIB_INCLUD	 	:=  $(patsubst %, -I %, $(LIB_INCDIRS))		
UTIL_INCLUD 	:=  $(patsubst %, -I %, $(UTIL_INCDIRS))	
# PROJECT_INCLID	:=  $(patsubst %, -I %, $(PROJECT_INCDIRS))

UTIL_CFILES		:=  $(foreach dir, $(UTIL_SRCDIRS), $(wildcard $(dir)/*.c))
LIB_CFILES		:=  $(foreach dir, $(LIB_SRCDIRS), $(wildcard $(dir)/*.c))
# PROJECT_CFILES	:=  $(foreach dir, $(PROJECT_SRCDIRS), $(wildcard $(dir)/*.c))

# DAEMON_OBJS 	:=  $(patsubst %.c, $(DAEMON_DIR)/%.o, $(notdir $(DAEMON_CFILES)))
UTIL_OBJS	 	:=  $(patsubst %.c, $(UTIL_DIR)/%.o, $(notdir $(UTIL_CFILES)))
LIB_OBJS	 	:=  $(patsubst %.c, $(LIB_DIR)/%.o, $(notdir $(LIB_CFILES)))
# PROJECT_OBJS	:=  $(patsubst %.c, $(PROJECT_DIR)/%.o, $(notdir $(PROJECT_CFILES)))

# VPATH			:= 	$(DAEMON_SRCDIRS)  $(UTIL_SRCDIRS)  $(LIB_SRCDIRS)  $(PROJECT_SRCDIRS)
VPATH			:= 	$(UTIL_SRCDIRS)  $(LIB_SRCDIRS) 


# Dependences               
# PROJECT_DEPENDS +=  -lubox -lubus -ljson-c -lblobmsg_json -luci -lpthread
# UTIL_DEPENDS 	:=  -lubox -lubus -ljson-c -lblobmsg_json -luci
# LIB_DEPENDS 	:=  -lubox -lubus -ljson-c -lblobmsg_json

UTIL_DEPENDS 	+=  -ljson-c -luci -lpthread -lreadline -lncurses 
LIB_DEPENDS 	+=  -ljson-c -luci -lpthread -luci
# PROJECT_DEPENDS +=  -ljson-c -luci -lpthread

# all:	$(EXE_DIR)/$(DAEMON) $(EXE_DIR)/$(UTIL) $(EXE_DIR)/$(LIBRARIES) $(EXE_DIR)/$(PROJECT)
all:	$(EXE_DIR)/$(UTIL) $(EXE_DIR)/$(LIBRARIES) 

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
# $(PROJECT_DIR)/%.o : %.c
# 	@echo "Project building file: $<"
# 	$(CC) -c $(CFLAG) ${PROJECT_INCLID}  $(PROJECT_DEPENDS) $< -o $@ 

# $(EXE_DIR)/$(PROJECT): $(PROJECT_OBJS)
# 	@echo "Linking target: $@"
# 	$(CC) $^ -o $@ $(PROJECT_DEPENDS)	

.PHONY: clean
clean:
	rm -rf $(UTIL_DIR) $(LIB_DIR) $(EXE_DIR)
# rm -rf $(DAEMON_DIR) $(UTIL_DIR) $(LIB_DIR) $(EXE_DIR) $(PROJECT)