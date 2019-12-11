package java_lite_simple_server;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {
    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");
        int ret = OCMain.initPlatform("Intel");
        ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0", "ocf.res.1.0.0");
        Light.name = "John's Light";
        Light.power = 0;
        Light.state = false;
        Counter.name = "John's Counter";
        Counter.count = 0;

        OCMain.setRandomPinHandler(new RandomPinHandler());

        OCSoftwareUpdate.setImpl(new OCSoftwareUpdateHandler() {
            @Override
            public int validatePURL(String url) {
                System.out.println("swupdate validating url " + url);
                try {
                    URL urlObject = new URL(url);
                    URLConnection conn = urlObject.openConnection();
                    conn.connect();
                } catch (MalformedURLException e) {
                    System.err.println("Software Update URL is not in a valid form: " + url);
                    return -1;
                } catch (IOException e) {
                    System.err.println("Connection to Software Update URL could not be established: " + url);
                    return -1;
                }
                return 0;
            }

            @Override
            public int checkNewVersion(long device, String url, String version) {
                System.out.println("swupdate checkNewVersion: device = " + device + ", url = " + url);
                if (url == null) {
                    OCSoftwareUpdate.notifyDone(device, OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_INVALID_URL);
                    return -1;
                }
                if (version != null) {
                    System.out.println("swupdate new version = " + version);
                }
                OCSoftwareUpdate.notifyNewVersionAvailable(device, "10.0",
                        OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
                return 0;
            }

            @Override
            public int downloadUpdate(long device, String url) {
                System.out.println("swupdate downloadUpdate: device = " + device + ", url = " + url);
                OCSoftwareUpdate.notifyDownload(device, "10.0", OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
                return 0;
            }

            @Override
            public int performUpgrade(long device, String url) {
                System.out.println("swupdate performUpgrade: device = " + device + ", url = " + url);
                OCSoftwareUpdate.notifyUpgrading(device, "10.0", System.currentTimeMillis(),
                        OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
                OCSoftwareUpdate.notifyDone(device, OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
                return 0;
            }
        });

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
