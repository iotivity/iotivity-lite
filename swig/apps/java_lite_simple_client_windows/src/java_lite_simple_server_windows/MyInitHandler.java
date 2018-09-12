package java_lite_simple_server_windows;

import org.iotivity.*;
import org.iotivity.MainInitHandler;

public class MyInitHandler implements MainInitHandler {
    @Override
    public int initilize() {
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
        OCMain.doIPDiscovery("core.light", discoveryHandler);
    }

    @Override
    public void signalEventLoop() {
        System.out.println("inside MyInitHandler.signalEventLoop()");
        Client.lock.lock();
        try {
            Client.cv.signalAll();
        } finally {
            Client.lock.unlock();
        }
    }
}
