package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ObtInitHandler implements OCMainInitHandler {

    private OcPlatform obtPlatform;

    public ObtInitHandler(OcPlatform obtPlatform) {
        this.obtPlatform = obtPlatform;
    }

    @Override
    public int initialize() {
        System.out.println("inside ObtInitHandler.initilize()");

        int ret = obtPlatform.platformInit("OBT");
        if (ret >= 0) {
            OcDevice device = new OcDevice("/oic/d", "oic.d.dots", "OBT", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            ret |= obtPlatform.addDevice(device);
            // Note: device must be added to platform before additional resource
            // types can be added
            device.bindResourceType("oic.d.ams");
            device.bindResourceType("oic.d.cms");
        }

        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside ObtInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside ObtInitHandler.requestEntry()");
    }
}
