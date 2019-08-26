package org.iotivity.oc;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OcCloudContext {

    private OCCloudContext nativeCloudContext;
    private OcCloudStore ocCloudStore;
    private OcLink rdPublishResources;
    private OcLink rdPublishedResources;
    private OcLink rdDeleteResources;
    private OcResource ocCloudConf;

    OcCloudContext(OCCloudContext nativeCloudContext) {
        this.nativeCloudContext = nativeCloudContext;
    }

    public void setStore(OcCloudStore value) {
        ocCloudStore = value;
        nativeCloudContext.setStore(value.getNativeCloudStore());
    }

    public OcCloudStore getStore() {
        return ocCloudStore;
    }

    public void setCloudEndpointState(OCSessionState value) {
        nativeCloudContext.setCloudEndpointState(value);
    }

    public OCSessionState getCloudEndpointState() {
        return nativeCloudContext.getCloudEndpointState();
    }

    public void setCloudEndpoint(OCEndpoint value) {
        nativeCloudContext.setCloudEndpoint(value);
    }

    public OCEndpoint getCloudEndpoint() {
        return nativeCloudContext.getCloudEndpoint();
    }

    public void setRetryCount(short value) {
        nativeCloudContext.setRetryCount(value);
    }

    public short getRetryCount() {
        return nativeCloudContext.getRetryCount();
    }

    public void setRetryRefreshTokenCount(short value) {
        nativeCloudContext.setRetryRefreshTokenCount(value);
    }

    public short getRetryRefreshTokenCount() {
        return nativeCloudContext.getRetryRefreshTokenCount();
    }

    public void setLastError(OCCloudError value) {
        nativeCloudContext.setLastError(value);
    }

    public OCCloudError getLastError() {
        return nativeCloudContext.getLastError();
    }

    public void setExpiresIn(int value) {
        nativeCloudContext.setExpiresIn(value);
    }

    public int getExpiresIn() {
        return nativeCloudContext.getExpiresIn();
    }

    public void setRdPublishResources(OcLink value) {
        rdPublishResources = value;
        nativeCloudContext.setRdPublishResources(value.getNativeLink());
    }

    public OcLink getRdPublishResources() {
        return rdPublishResources;
    }

    public void setRdPublishedResources(OcLink value) {
        rdPublishedResources = value;
        nativeCloudContext.setRdPublishedResources(value.getNativeLink());
    }

    public OcLink getRdPublishedResources() {
        return rdPublishedResources;
    }

    public void setRdDeleteResources(OcLink value) {
        rdDeleteResources = value;
        nativeCloudContext.setRdDeleteResources(value.getNativeLink());
    }

    public OcLink getRdDeleteResources() {
        return rdDeleteResources;
    }

    public void setRdDeleteAll(boolean value) {
        nativeCloudContext.setRdDeleteAll(value);
    }

    public boolean getRdDeleteAll() {
        return nativeCloudContext.getRdDeleteAll();
    }

    public void setCloudConf(OcResource value) {
        ocCloudConf = value;
        nativeCloudContext.setCloudConf(value.getNativeResource());
    }

    public OcResource getCloudConf() {
        return ocCloudConf;
    }

    public void setCloudManager(boolean value) {
        nativeCloudContext.setCloudManager(value);
    }

    public boolean getCloudManager() {
        return nativeCloudContext.getCloudManager();
    }

    OCCloudContext getNativeCloudContext() {
        return nativeCloudContext;
    }
}
