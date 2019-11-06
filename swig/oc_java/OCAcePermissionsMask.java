package org.iotivity;

public class OCAcePermissionsMask {
    public static final int NONE = 0;
    public static final int CREATE = 1 << 0;
    public static final int RETRIEVE = 1 << 1;
    public static final int UPDATE = 1 << 2;
    public static final int DELETE = 1 << 3;
    public static final int NOTIFY = 1 << 4;
}