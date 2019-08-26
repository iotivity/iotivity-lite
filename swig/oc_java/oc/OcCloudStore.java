package org.iotivity.oc;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OcCloudStore {

    private OCCloudStore nativeCloudStore;
    private OcDevice device;

    public OcCloudStore() {
        nativeCloudStore = new OCCloudStore();
    }

    public void setCiServer(String value) {
        nativeCloudStore.setCi_server(value);
    }

    public String getCiServer() {
        return nativeCloudStore.getCi_server();
    }

    public void setAuthProvider(String value) {
        nativeCloudStore.setAuth_provider(value);
    }

    public String getAuthProvider() {
        return nativeCloudStore.getAuth_provider();
    }

    public void setUid(String value) {
        nativeCloudStore.setUid(value);
    }

    public String getUid() {
        return nativeCloudStore.getUid();
    }

    public void setAccessToken(String value) {
        nativeCloudStore.setAccess_token(value);
    }

    public String getAccessToken() {
        return nativeCloudStore.getAccess_token();
    }

    public void setRefreshToken(String value) {
        nativeCloudStore.setRefresh_token(value);
    }

    public String getRefreshToken() {
        return nativeCloudStore.getRefresh_token();
    }

    public void setSid(String value) {
        nativeCloudStore.setSid(value);
    }

    public String getSid() {
        return nativeCloudStore.getSid();
    }

    public void setStatus(short value) {
        nativeCloudStore.setStatus(value);
    }

    public short getStatus() {
        return nativeCloudStore.getStatus();
    }

    OCCloudStore getNativeCloudStore() {
        return nativeCloudStore;
    }
}
