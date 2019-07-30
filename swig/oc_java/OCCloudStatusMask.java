package org.iotivity;

public class OCCloudStatusMask {
    public static final int OC_CLOUD_INITIALIZED = 0;
    public static final int OC_CLOUD_REGISTERED = 1;
    public static final int OC_CLOUD_LOGGED_IN = 2;
    public static final int OC_CLOUD_TOKEN_EXPIRY = 4;
    public static final int OC_CLOUD_REFRESHED_TOKEN = 8;
    public static final int OC_CLOUD_LOGGED_OUT = 16;
    public static final int OC_CLOUD_FAILURE = 32;
    public static final int OC_CLOUD_DEREGISTERED = 64;
}