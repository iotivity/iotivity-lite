package java_multi_device_client;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {
    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initiliaze()");
        int ret = OCMain.initPlatform("FridgeRemote");
        ret |= OCMain.addDevice("/oic/d", "oic.d.remote", "My remote", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        // do nothing used for Servers.
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
        MyDiscoveryHandler discoveryHandler = new MyDiscoveryHandler();
        OCMain.doIPDiscovery(null, discoveryHandler);
        OCMain.setDelayedHandler(new GetPandDTriggerHandler(), 10);
    }
}
