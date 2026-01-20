LIB_NAME=libvcknots_wallet
OUT_DIR=output

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
GOPATH := $(shell go env GOPATH)

HOST_ARCH :=
ifeq ($(UNAME_S),Linux)
    HOST_ARCH := linux-x86_64
else ifeq ($(UNAME_S),Darwin)
    HOST_ARCH := darwin-x86_64
endif

# iOS settings
IPHONE_SDK=$(shell xcrun --sdk iphoneos --show-sdk-path)
IPHONE_SDK_CLANG=$(shell xcrun --sdk iphoneos --find clang)

IPHONE_SIMULATOR_SDK=$(shell xcrun --sdk iphonesimulator --show-sdk-path)
IPHONE_SIMULATOR_SDK_CLANG=$(shell xcrun --sdk iphonesimulator --find clang)



# Android settings
NEED_ANDROID := $(filter android android-arm64 all,$(MAKECMDGOALS))

ifeq ($(NEED_ANDROID),)
    $(info "Skipping Android NDK lookup (not building Android targets)")
else
    NDK_PATH :=
    ifneq ($(ANDROID_NDK_HOME),)
        ifeq ("$(wildcard $(ANDROID_NDK_HOME)/source.properties)","")
            $(warning "Warning: ANDROID_NDK_HOME is set to '$(ANDROID_NDK_HOME)' but it doesn't seem to be a valid NDK directory.")
        else
            NDK_PATH := $(ANDROID_NDK_HOME)
        endif
    endif

    ifeq ($(NDK_PATH),)
        SDK_PATH :=
        ifneq ($(ANDROID_HOME),)
            SDK_PATH := $(ANDROID_HOME)
        else ifneq ($(ANDROID_SDK_ROOT),)
            SDK_PATH := $(ANDROID_SDK_ROOT)
        endif

        ifneq ($(SDK_PATH),)
            LATEST_NDK_DIR := $(lastword $(sort $(wildcard $(SDK_PATH)/ndk/*)))
            ifneq ($(LATEST_NDK_DIR),)
                NDK_PATH := $(LATEST_NDK_DIR)
            endif
        endif
    endif

    ifeq ($(NDK_PATH),)
        DEFAULT_SDK_PATH :=
        ifeq ($(UNAME_S),Linux)
            DEFAULT_SDK_PATH := $(HOME)/Android/Sdk
        else ifeq ($(UNAME_S),Darwin)
            DEFAULT_SDK_PATH := $(HOME)/Library/Android/sdk
        endif

        ifneq ("$(wildcard $(DEFAULT_SDK_PATH))", "")
            LATEST_NDK_DIR := $(lastword $(sort $(wildcard $(DEFAULT_SDK_PATH)/ndk/*)))
            ifneq ($(LATEST_NDK_DIR),)
                NDK_PATH := $(LATEST_NDK_DIR)
            endif
        endif
    endif

    ifeq ($(NDK_PATH),)
        $(error "Android NDK path could not be found. Please set ANDROID_NDK_HOME environment variable, or install NDK via Android Studio.")
    else
        $(info "Using Android NDK at: $(NDK_PATH)")
    endif
endif

ANDROID_API_LEVEL=28

ios-modulemap:
	@echo "Generating module.modulemap..."
	@mkdir -p ${OUT_DIR}/ios
	@echo "framework module VcknotsWallet {\n  header \"${LIB_NAME}.h\"\n  export *\n}" > ${OUT_DIR}/ios/module.modulemap

ios-arm64: ios-modulemap
		@echo "Building for iOS (arm64)..."
		CGO_ENABLED=1 \
		GOOS=ios \
		GOARCH=arm64 \
		CC=${IPHONE_SDK_CLANG} \
		CGO_CFLAGS="-isysroot ${IPHONE_SDK}" \
		go build -ldflags="-s -w" -trimpath -buildmode=c-archive -o ${OUT_DIR}/ios/ios-arm64/${LIB_NAME}.a
		
		mkdir -p ${OUT_DIR}/ios/ios-arm64/include
		mv ${OUT_DIR}/ios/ios-arm64/${LIB_NAME}.h ${OUT_DIR}/ios/ios-arm64/include/${LIB_NAME}.h
		cp ${OUT_DIR}/ios/module.modulemap ${OUT_DIR}/ios/ios-arm64/include/module.modulemap

ios-simulator:
		@echo "Building for iOS Simulator..."
		CGO_ENABLED=1 \
		GOOS=ios \
		GOARCH=amd64 \
		CC="${IPHONE_SIMULATOR_SDK_CLANG} -arch x86_64" \
		CGO_CFLAGS="-isysroot ${IPHONE_SIMULATOR_SDK}" \
		go build -ldflags="-s -w" -trimpath -buildmode=c-archive -o ${OUT_DIR}/ios/ios-simulator-x86_64/${LIB_NAME}.a

		CGO_ENABLED=1 \
		GOOS=ios \
		GOARCH=arm64 \
		CC="${IPHONE_SIMULATOR_SDK_CLANG} -arch arm64" \
		CGO_CFLAGS="-isysroot ${IPHONE_SIMULATOR_SDK}" \
		go build -ldflags="-s -w" -trimpath -buildmode=c-archive -o ${OUT_DIR}/ios/ios-simulator-arm64/${LIB_NAME}.a

		mkdir -p ${OUT_DIR}/ios/ios-simulator/include
		lipo -create ${OUT_DIR}/ios/ios-simulator-x86_64/${LIB_NAME}.a ${OUT_DIR}/ios/ios-simulator-arm64/${LIB_NAME}.a -output ${OUT_DIR}/ios/ios-simulator/${LIB_NAME}.a
		cp ${OUT_DIR}/ios/ios-simulator-arm64/${LIB_NAME}.h ${OUT_DIR}/ios/ios-simulator/include/${LIB_NAME}.h
		cp ${OUT_DIR}/ios/module.modulemap ${OUT_DIR}/ios/ios-simulator/include/module.modulemap
		rm -rf ${OUT_DIR}/ios/ios-simulator-x86_64/${LIB_NAME}.a ${OUT_DIR}/ios/ios-simulator-arm64/${LIB_NAME}.a

ios: ios-arm64 ios-simulator
		rm -rf ${OUT_DIR}/ios/VcknotsWallet.xcframework
		xcodebuild -create-xcframework \
			-library ${OUT_DIR}/ios/ios-arm64/${LIB_NAME}.a \
			-headers ${OUT_DIR}/ios/ios-arm64/include \
			-library ${OUT_DIR}/ios/ios-simulator/${LIB_NAME}.a \
			-headers ${OUT_DIR}/ios/ios-simulator/include \
			-output ${OUT_DIR}/ios/VcknotsWallet.xcframework
		cp -r ${OUT_DIR}/ios/VcknotsWallet.xcframework ./wrappers/vcknots_wallet_dart_wrapper/ios/Frameworks/
		mkdir -p ./wrappers/vcknots_wallet_dart_wrapper/ios/Classes
		cp ${OUT_DIR}/ios/ios-arm64/include/*.h ./wrappers/vcknots_wallet_dart_wrapper/ios/Classes/
		@echo "iOS libraries built."

android-arm64:
		@echo "Building for Android (arm64-v8a)..."
		CGO_ENABLED=1 \
		GOOS=android \
		GOARCH=arm64 \
		CC=${NDK_PATH}/toolchains/llvm/prebuilt/${HOST_ARCH}/bin/aarch64-linux-android${ANDROID_API_LEVEL}-clang \
		CGO_CFLAGS="-DANDROID -DANDROID_ABI=arm64-v8a -DANDROID_API=${ANDROID_API_LEVEL}" \
		go build -ldflags="-s -w" -trimpath -buildmode=c-shared -o ${OUT_DIR}/android/arm64-v8a/${LIB_NAME}.so
		mkdir -p ./wrappers/vcknots_wallet_dart_wrapper/android/src/main/jniLibs/arm64-v8a/
		cp ${OUT_DIR}/android/arm64-v8a/${LIB_NAME}.so ./wrappers/vcknots_wallet_dart_wrapper/android/src/main/jniLibs/arm64-v8a/

android: android-arm64
		@echo "All Android libraries built."

all: ios android
	cd ./wrappers/vcknots_wallet_dart_wrapper; dart run ffigen --config ffigen.yaml

format:
	go fmt ./...

clean:
		rm -rf ${IOS_OUT_DIR}
		rm -rf ${OUT_DIR}

test:
	go test -cover ./... -coverprofile=cover.out

lint:
	${GOPATH}/bin/staticcheck ./...

.PHONY:
	ios-arm64
	ios-simulator
	ios
	android-arm64
	android
	clean
	test
	lint
	format
