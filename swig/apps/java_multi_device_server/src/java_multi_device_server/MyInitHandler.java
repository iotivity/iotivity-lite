package java_multi_device_server;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {
    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");

        int ret = OCMain.initPlatform("Refrigerator");
        ret |= OCMain.addDevice("/oic/d", "oic.d.refrigerator", "My fridge", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
        ret |= OCMain.addDevice("/oic/d", "oic.d.thermostat", "My thermostat", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");

        // Initialize fridge device values
        Fridge.filter = 0;
        Fridge.rapidFreeze = false;
        Fridge.defrost = false;
        Fridge.rapidCool = false;

        // Initialize Thermostat
        Thermostat.temperature = 0.0;
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");

        OCResource resource = OCMain.newResource("myfridge", "/fridge/1", (short) 1, 0);
        OCMain.resourceBindResourceType(resource, "oic.r.refrigeration");
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.A);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetFridge());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostFridge());
        OCMain.addResource(resource);

        OCResource resource1 = OCMain.newResource("tempsetter", "/temp/1", (short) 1, 1);
        OCMain.resourceBindResourceType(resource1, "oic.r.temperature");
        OCMain.resourceBindResourceInterface(resource1, OCInterfaceMask.A | OCInterfaceMask.S);
        OCMain.resourceSetDefaultInterface(resource1, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(resource1, true);
        OCMain.resourceSetPeriodicObservable(resource1, 1);
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_GET, new GetTemp());
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_POST, new PostTemp());
        OCMain.addResource(resource1);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }
}
