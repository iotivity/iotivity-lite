package java_onboarding_tool;

import org.iotivity.*;

public class ObtInitHandler implements OCMainInitHandler {

    @Override
    public int initialize() {
        System.out.println("inside ObtInitHandler.initilize()");
        int ret = OCMain.initPlatform("OCF");
        ret |= OCMain.addDevice("/oic/d", "oic.d.dots", "OBT", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
        OCMain.deviceBindResourceType(0, "oic.d.ams");
        OCMain.deviceBindResourceType(0, "oic.d.cms");
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside ObtInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside ObtInitHandler.requestEntry()");
        OCObt.init();
    }
}
