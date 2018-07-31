package java_lite_simple_server_windows;

import org.iotivity.*;
import org.iotivity.MainInitHandler;

public class MyInitHandler implements MainInitHandler {
    @Override
    public int initilize() {
        System.out.println("inside MyInitHandler.initiliaze()");
        int ret = OCMain.initPlatform("Intel");
        ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0", "ocf.res.1.0.0");
        Light.name = "John's Light";
        Light.power = 0;
        Light.state = false;
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");
        Resource resource = new Resource("", "/a/light", (short)2, 0);
        resource.bindResourceType("core.light");
        resource.bindResourceType("core.brightlight");
        resource.bindResourceInterface((short) OCInterfaceMask.RW); //Fix the type the bindResourceInterface to take OCInterfaceMask
        resource.setDefaultInterface(OCInterfaceMask.RW);
        resource.setDiscoverable(true);
        resource.setPeriodicObservable(1);
        resource.setRequestHandler(OCMethod.OC_GET, new GetLight());
        resource.setRequestHandler(OCMethod.OC_PUT, new PutLight());
        resource.setRequestHandler(OCMethod.OC_POST, new PostLight());
        OCMain.addResource(resource);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }

    @Override
    public void signalEventLoop() {
        System.out.println("inside MyInitHandler.signalEventLoop()");
        server.lock.lock();
        try {
            server.cv.signalAll();
        } finally {
            server.lock.unlock();
        }
    }
}
