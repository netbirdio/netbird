package iface

type MobileIFaceArguments struct {
	TunAdapter TunAdapter // only for Android
	TunFd      int        // only for iOS
}
