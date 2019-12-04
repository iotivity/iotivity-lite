package java_lite_simple_server;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {
    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");
        int ret = OCMain.initPlatform("Intel");
        ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Lamp", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
        Light.name = "John's Light";
        Light.power = 0;
        Light.state = false;
        Counter.name = "John's Counter";
        Counter.count = 0;

        OCMain.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");
        OCResource resource = OCMain.newResource("", "/a/light", (short) 2, 0);
        OCMain.resourceBindResourceType(resource, "oic.r.switch.binary");
        OCMain.resourceBindResourceType(resource, "oic.r.light.dimming");
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetLight());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, new PutLight());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostLight());
        OCMain.addResource(resource);

        // for running with client_collections_linux
        OCResource resource1 = OCMain.newResource("lightbulb", "/light/1", (short) 1, 0);
        OCMain.resourceBindResourceType(resource1, "oic.r.light");
        OCMain.resourceBindResourceInterface(resource1, OCInterfaceMask.RW);
        OCMain.resourceSetDefaultInterface(resource1, OCInterfaceMask.RW);
        OCMain.resourceSetDiscoverable(resource1, true);
        OCMain.resourceSetPeriodicObservable(resource1, 1);
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_GET, new GetLight());
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_PUT, new PutLight());
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_POST, new PostLight());
        OCMain.addResource(resource1);

        OCResource resource2 = OCMain.newResource("counter", "/count/1", (short) 1, 0);
        OCMain.resourceBindResourceType(resource2, "oic.r.counter");
        OCMain.resourceBindResourceInterface(resource2, OCInterfaceMask.R);
        OCMain.resourceSetDefaultInterface(resource2, OCInterfaceMask.R);
        OCMain.resourceSetDiscoverable(resource2, true);
        OCMain.resourceSetPeriodicObservable(resource2, 1);
        OCMain.resourceSetRequestHandler(resource2, OCMethod.OC_GET, new GetCounter());
        OCMain.resourceSetRequestHandler(resource2, OCMethod.OC_POST, new PostCounter());
        OCMain.addResource(resource2);

        OCResource collection = OCMain.newCollection("roomlights", "/lights", (short) 1, 0);
        OCMain.resourceBindResourceType(collection, "oic.wk.col");
        OCMain.resourceSetDiscoverable(collection, true);

        OCLink link1 = OCMain.newLink(resource1);
        OCMain.collectionAddLink(collection, link1);

        OCLink link2 = OCMain.newLink(resource2);
        OCMain.collectionAddLink(collection, link2);
        OCMain.addCollection(collection);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }
}
