package org.iotivity.oc;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OcCloud {

    public OcCloud() {
    }

    public OcCloudContext getContext(OcDevice device) {
        if (device == null) {
            throw new IllegalArgumentException("OcDevice cannot be null");
        }
        return new OcCloudContext(OCCloud.getContext(device.getDeviceIndex()));
    }

    public int managerStart(OcCloudContext ctx, OCCloudHandler callback) {
        return OCCloud.managerStart(ctx.getNativeCloudContext(), callback);
    }

    public int managerStop(OcCloudContext ctx) {
        return OCCloud.managerStop(ctx.getNativeCloudContext());
    }

    public int registerCloud(OcCloudContext ctx, OCCloudHandler callback) {
        return OCCloud.registerCloud(ctx.getNativeCloudContext(), callback);
    }

    public int login(OcCloudContext ctx, OCCloudHandler callback) {
        return OCCloud.login(ctx.getNativeCloudContext(), callback);
    }

    public int logout(OcCloudContext ctx, OCCloudHandler callback) {
        return OCCloud.logout(ctx.getNativeCloudContext(), callback);
    }

    public int deregisterCloud(OcCloudContext ctx, OCCloudHandler callback) {
        return OCCloud.deregisterCloud(ctx.getNativeCloudContext(), callback);
    }

    public int refreshToken(OcCloudContext ctx, OCCloudHandler callback) {
        return OCCloud.refreshToken(ctx.getNativeCloudContext(), callback);
    }

    public int getTokenExpiry(OcCloudContext ctx) {
        return OCCloud.getTokenExpiry(ctx.getNativeCloudContext());
    }

    public int addResource(OcResource resource) {
        return OCCloud.addResource(resource.getNativeResource());
    }

    public void deleteResource(OcResource resource) {
        OCCloud.deleteResource(resource.getNativeResource());
    }

    public int publishResources(OcDevice device) {
        return OCCloud.publishResources(device.getDeviceIndex());
    }
}
