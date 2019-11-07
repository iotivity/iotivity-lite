package java_lite_simple_client;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {
    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initiliaze()");
        int ret = OCMain.initPlatform("Apple");
        ret |= OCMain.addDevice("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
        MyDiscoveryHandler discoveryHandler = new MyDiscoveryHandler();
        OCMain.doIPDiscovery("oic.r.switch.binary", discoveryHandler);
    }
}
