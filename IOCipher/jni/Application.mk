APP_ABI := armeabi armeabi-v7a x86 x86_64
APP_PROJECT_PATH := $(shell pwd)
APP_BUILD_SCRIPT := $(APP_PROJECT_PATH)/jni/Android.mk
APP_STL := c++_static
#
EXTERNAL_PATH := $(APP_PROJECT_PATH)/external
