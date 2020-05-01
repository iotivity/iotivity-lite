package org.iotivity;

public interface OCSoftwareUpdateHandler {
    public int validatePURL(String url);
    public int checkNewVersion(long device, String url, String version);
    public int downloadUpdate(long device, String url);
    public int performUpgrade(long device, String url);
}