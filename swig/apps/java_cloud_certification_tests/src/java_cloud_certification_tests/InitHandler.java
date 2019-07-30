package java_cloud_certification_tests;

import org.iotivity.*;

public class InitHandler implements OCMainInitHandler {

    @Override
    public int initialize() {
        System.out.println("inside Cloud Certification Test InitHandler.initilize()");
        int ret = OCMain.initPlatform("OCF");
        ret |= OCMain.addDevice("/oic/d", "oic.d.cloudDevice", "Cloud Device", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside Cloud Certification Test InitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside Cloud Certification Test InitHandler.requestEntry()");
    }
}
