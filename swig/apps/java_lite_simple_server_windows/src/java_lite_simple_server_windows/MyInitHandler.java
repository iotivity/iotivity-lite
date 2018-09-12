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
        OCResource resource = OCMain.newResource("", "/a/light", (short) 2, 0);
        OCMain.resourceBindResourceType(resource, "core.light");
        OCMain.resourceBindResourceType(resource, "core.brightlight");
        OCMain.resourceBindResourceInterface(resource, (short) OCInterfaceMask.RW);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetLight());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, new PutLight());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostLight());
        OCMain.addResource(resource);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }

    @Override
    public void signalEventLoop() {
        System.out.println("inside MyInitHandler.signalEventLoop()");
        Server.lock.lock();
        try {
            Server.cv.signalAll();
        } finally {
            Server.lock.unlock();
        }
    }
}
