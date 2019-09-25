package java_oc_channel_change_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class InitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;

    public InitHandler(OcPlatform platform) {
        this.platform = platform;
    }

    @Override
    public int initialize() {
        System.out.println("inside InitHandler.initialize()");

        int ret = platform.platformInit("Apple");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.phone", "Kishen's iPhone", "ocf.1.0.0", "ocf.res.1.0.0");
            ret |= platform.addDevice(device);
        }

        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside InitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside InitHandler.requestEntry()");
    }
}
