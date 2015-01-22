#***********************************************************************
#
#  Copyright (c) 2014-2016  I-MOVE(SHENTHEN) Co., Ltd.
#  All Rights Reserved
#
#  author: lishengming
#  create date: 2014-11-4
# 
# Unless you and I-MOVE execute a separate written software license 
# agreement governing use of this software, this software is licensed 
# to you under the terms of the GNU General Public License version 2 
# (the "GPL"), with the following added to such license:
# 
#    As a special exception, the copyright holders of this software give 
#    you permission to link this software with independent modules, and 
#    to copy and distribute the resulting executable under terms of your 
#    choice, provided that you also meet, for each linked independent 
#    module, the terms and conditions of the license of that module. 
#    An independent module is a module which is not derived from this
#    software.  The special exception does not apply to any modifications 
#    of the software.  
# 
# Not withstanding the above, under no circumstances may you combine 
# this software in any way with any other I-MOVE software provided 
# under a license other than the GPL, without I-MOVE's express prior 
# written consent. 
#
#
#***********************************************************************

PER_AUTH_LIB := libper_auth.so
PER_AUTH_OBJS := per_auth.o
PER_AUTH_SRC := per_auth.c
PER_AUTH_H := per_auth.h
SHARED=-shared -o
FPIC=-fPIC -c
PER_AUTH_CFLAGS := $(CFLAGS)

all: $(PER_AUTH_LIB)

$(PER_AUTH_LIB):$(PER_AUTH_OBJS)
	$(CC) $(PER_AUTH_OBJS) $(SHARED) -fPIC -o $(PER_AUTH_LIB)
$(PER_AUTH_OBJS):$(PER_AUTH_SRC) $(PER_AUTH_H)
	$(CC) $(FPIC) $(PER_AUTH_SRC)
	
clean: 
	rm -f $(PER_AUTH_LIB) *.o














