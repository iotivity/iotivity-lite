package org.iotivity;

import org.junit.*;
import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class OCOwnershipTransferMethodsTest {
    
    // wait time chosen arbitrarily  
    private final int WAIT_TIME_SHORT = 3;
    private final int WAIT_TIME_MED = 10;
    private final int WAIT_TIME_LONG = 30;
    
    private static CountDownLatch requestEntryExecuted;
    private static CountDownLatch getLightExecuted;
    
    public static class BinarySwitch {
        public static boolean value;
    }
    
    private static OCRequestHandler getLight = new OCRequestHandler() {
        
        @Override
        public void handler(OCRequest request, int interfaces) {
            System.out.println("Inside the MultiDevice GetLight RequestHandler");
            System.out.println("GET:");
            CborEncoder root = OCRep.beginRootObject();
            switch (interfaces) {
            case OCInterfaceMask.BASELINE: {
                OCMain.processBaselineInterface(request.getResource());
                /* fall through */
            }
            case OCInterfaceMask.RW: {
                OCRep.setBoolean(root, "value", BinarySwitch.value);
                break;
            }
            default:
                break;
            }
            OCRep.endRootObject();
            OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
            getLightExecuted.countDown();
        }
    };
    
    private static OCRequestHandler putPostLight = new OCRequestHandler() {
        
        @Override
        public void handler(OCRequest request, int interfaces) {
            System.out.println("Inside the MultiDevice GetLight RequestHandler");
            System.out.println("PUT/POST:");
        }
    };
    
    private static OCMainInitHandler init = new OCMainInitHandler() {
        @Override
        public int initialize() {
            System.out.println("inside MultiDevice initilize()");
            int ret = OCMain.initPlatform("Desktop Computer");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.computer.desktop", "Test OBT", "ocf.1.0.0", "ocf.res.1.0.0");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Test Light", "ocf.1.0.0", "ocf.res.1.0.0");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.lightingcontrol", "Test Light Control", "ocf.1.0.0", "ocf.res.1.0.0");
            BinarySwitch.value = true;
            assertEquals(0, ret);
            return ret;
        }

        @Override
        public void registerResources() {
            System.out.println("inside MultiDevice registerResources()");
            OCResource resource = OCMain.newResource("", "/light/switch", (short) 1, 1);
            assertNotNull(resource);
            OCMain.resourceBindResourceType(resource, "oic.r.switch.binary");
            OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.RW);
            OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.RW);
            OCMain.resourceSetDiscoverable(resource, true);
            OCMain.resourceSetPeriodicObservable(resource, 1);
            OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, getLight);
            OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, putPostLight);
            OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, putPostLight);
            assertTrue(OCMain.addResource(resource));
        }

        @Override
        public void requestEntry() {
            System.out.println("inside MultiDevice requestEntry()");
            assertNotEquals(-1, OCObt.init());
            System.out.println(OCUuidUtil.uuidToString(OCCoreRes.getDeviceId(0)) + " " + OCCoreRes.getDeviceInfo(0).getName());
            System.out.println(OCUuidUtil.uuidToString(OCCoreRes.getDeviceId(1)) + " " + OCCoreRes.getDeviceInfo(1).getName());
            System.out.println(OCUuidUtil.uuidToString(OCCoreRes.getDeviceId(2)) + " " + OCCoreRes.getDeviceInfo(2).getName());
//            if (0 > OCObt.discoverUnownedDevices(new OCObtDiscoveryHandler() {
//                @Override
//                public void handler(OCUuid uuid, OCEndpoint endpoints) {
//                    System.out.println("inside MultiDevice OCObtDiscoveryHandler");
//                    String deviceId = OCUuidUtil.uuidToString(uuid);
//                    System.out.println("Discovered unowned device: "+ deviceId);
////                    System.out.println("\nDiscovered unowned device: "+ deviceId + " at:");
////                    while (endpoints != null) {
////                        
////                        String endpointStr = OCEndpointUtil.toString(endpoints);
////                        System.out.println(endpointStr);
////                        endpoints = endpoints.getNext();
////                    }
//                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
//                        int ret = OCObt.performJustWorksOtm(OCCoreRes.getDeviceId(1), new OCObtDeviceStatusHandler() {
//                            @Override
//                            public void handler(OCUuid uuid, int status) {
//                                if (status >= 0) {
//                                    System.out.println("Successfully performed OTM on device " + OCUuidUtil.uuidToString(uuid));
//                                    System.out.println(OCUuidUtil.uuidToString(OCCoreRes.getDeviceId(1)) + " " + OCCoreRes.getDeviceInfo(1).getName());
//                                    OCSecurityAce ace = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_AUTH_CRYPT);
//                                    if (ace == null) {
//                                        System.out.println("\nERROR: Could not create ACE");
//                                        resetAllDevices();
//                                        return;
//                                    }
//                                    OCAceResource res = OCObt.aceNewResource(ace);
//                                    if (res == null) {
//                                        System.out.println("\nERROR: Could not allocate new resource for ACE");
//                                        OCObt.freeAce(ace);
//                                        resetAllDevices();
//                                        return;
//                                    }
//                                    OCObt.aceResourceSetWc(res, OCAceWildcard.OC_ACE_WC_ALL_SECURED);
//                                    OCObt.aceAddPermission(ace, (OCAcePermissionsMask.RETRIEVE | OCAcePermissionsMask.UPDATE | OCAcePermissionsMask.NOTIFY));
//
//                                    //OCObt.aceAddPermission(ace, OCAcePermissionsMask.RETRIEVE);
//                                    //OCObt.aceAddPermission(ace, OCAcePermissionsMask.UPDATE);
//                                    //OCObt.aceAddPermission(ace, OCAcePermissionsMask.NOTIFY);
//                                    System.out.println("Provision ace on " + OCUuidUtil.uuidToString(uuid));
//                                    int ret = OCObt.provisionAce(uuid, ace, provisionAceHandler);
////                                    int ret = OCObt.provisionAce(OCCoreRes.getDeviceId(1), ace, provisionAceHandler);
//                                    if (ret >= 0) {
//                                        System.out.println("Successfully issued request to provision ACE");
//                                    } else {
//                                        System.out.println("\nERROR issuing request to provision ACE - return value: " + ret);
//                                        //resetAllDevices();
//                                    }
//                                } else {
//                                    System.out.println("\nERROR performing ownership transfer on device " + OCUuidUtil.uuidToString(uuid));
//                                    resetAllDevices();
//                                }
//                            }
//                        });
//                        if (ret >= 0) {
//                            System.out.println("\nSuccessfully issued request to perform ownership transfer");
//                        } else {
//                            System.out.println("\nERROR issuing request to perform ownership transfer");
//                        }
//                    }
//                    unownedDevices.add(uuid);
//                }
//            })) {
//                System.err.println("ERROR discovering un-owned Devices.");
//            }
            requestEntryExecuted.countDown();
        }
    };
    
    @Before
    public void setup() {
        System.out.println("setup");
        
        requestEntryExecuted = new CountDownLatch(1);
        
        String creds_path = "./unit_test_device_creds/";
        
        // Make sure the creds directory exists
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        // This onboards and runs the code we expect the security related files to be cleared each run.
        for(java.io.File file: directory.listFiles()) { 
            if (!file.isDirectory()) { 
                file.delete();
            }
        }
        
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        assertTrue(OCMain.mainInit(init) >= 0);
    }
    
    @After
    public void teardown() {
        System.out.println("teardown");
        OCMain.mainShutdown();
        OCObt.shutdown();
    }
    
    
    /*
     * 1. Discover Server
     * 1a. Call GET on Server verify it fails (not onboarded)
     * 1b. Call POST on Server verify it fails (not onboarded)
     * 2. Perform **Just works OTM**
     * 2a. Call GET on Server verify it fails (not provisioned)
     * 2b. Call POST on Server verify if fails (not provisioned)
     * 3. Provision Server using wildcard (provisioning is not being tested but is required for get post to succeed.)
     * 3a. Call GET on Server verify it succeeds
     * 3b. Call POST on Server verify is succeeds
     */
    @Test
    public void justWorksOTM() {
        try {
            System.out.println("justWorksOTM");
            assertTrue(requestEntryExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));

            CountDownLatch discoveryHandlerExecuted = new CountDownLatch(1);

            OCMain.doIPDiscovery("oic.r.switch.binary", new OCDiscoveryHandler() {
                @Override
                public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint, int resourcePropertiesMask) {
                    for (String type: types) {
                        if(type.equals("oic.r.switch.binary")) {
                            //Light.serverEndpoint = endpoint;
                            //Light.serverUri = uri;
                            System.out.println("\tResource " + uri + " hosted at endpoint(s):");
                            OCEndpoint ep = endpoint;
                            while (ep != null) {

                                String endpointStr = OCEndpointUtil.toString(ep);
                                System.out.println("\t\tendpoint: " + endpointStr);
                                System.out.println("\t\t\tendpoint.device " + ep.getDevice());
                                System.out.println("\t\t\tendpoint.flags " + ep.getFlags());
                                System.out.println("\t\t\tendpoint.interfaceIndex " + ep.getInterfaceIndex());
                                System.out.println("\t\t\tendpoint.version " + ep.getVersion().toString());
                                ep = ep.getNext();
                            }

                            CountDownLatch responseHandlerExecuted = new CountDownLatch(1); 
                            OCResponseHandler responseHandler = new OCResponseHandler() {
                                @Override
                                public void handler(OCClientResponse response) {
                                    System.out.println("Get Light Response Handler:");
                                    OCRepresentation rep = response.getPayload();
                                    assertNotNull(rep);
                                    while(rep != null) {
                                        switch(rep.getType()) {
                                        case OC_REP_BOOL:
                                            System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                                            break;
                                        case OC_REP_INT:
                                            System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                                            break;
                                        case OC_REP_STRING:
                                            System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getString());
                                            break;
                                        default:
                                            break;
                                        }
                                        rep = rep.getNext();
                                    }
                                    responseHandlerExecuted.countDown();
                                }
                            };
                            assertTrue(OCMain.doGet(uri, endpoint, null, responseHandler, OCQos.LOW_QOS));
                            // This will wait for a short while to make sure the response handler is not called.
                            // TODO find better way to indicate failure 
                            try {
                                assertFalse(responseHandlerExecuted.await(WAIT_TIME_SHORT, TimeUnit.SECONDS));
                            } catch (InterruptedException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                            discoveryHandlerExecuted.countDown();
                            return OCDiscoveryFlags.OC_STOP_DISCOVERY;
                        }
                    }
                    return null;
                }
            });
            assertTrue(discoveryHandlerExecuted.await(WAIT_TIME_LONG, TimeUnit.SECONDS));

            CountDownLatch discoverUnownedDevicesHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.discoverUnownedDevices(new OCObtDiscoveryHandler() {
                @Override
                public void handler(OCUuid uuid, OCEndpoint endpoints) {
                    System.out.println("inside MultiDevice OCObtDiscoveryHandler");
                    String deviceId = OCUuidUtil.uuidToString(uuid);
                    System.out.println("Discovered unowned device: "+ deviceId);
                    System.out.println("\nDiscovered unowned device: "+ deviceId + " at:");
                    while (endpoints != null) {
                        
                        String endpointStr = OCEndpointUtil.toString(endpoints);
                        System.out.println(endpointStr);
                        endpoints = endpoints.getNext();
                    }
                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
                        discoverUnownedDevicesHandlerExecuted.countDown();
                    }
                }
            }));
            assertTrue(discoverUnownedDevicesHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            CountDownLatch justWorksOtmHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.performJustWorksOtm(OCCoreRes.getDeviceId(1), new OCObtDeviceStatusHandler() {
                @Override
                public void handler(OCUuid uuid, int status) {
                    assertEquals(0, status);
                    justWorksOtmHandlerExecuted.countDown();
                }
            }));
            assertTrue(justWorksOtmHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            
            CountDownLatch discoverOwnedDevicesHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.discoverOwnedDevices(new OCObtDiscoveryHandler() {
                @Override
                public void handler(OCUuid uuid, OCEndpoint endpoints) {
                    System.out.println("inside MultiDevice OCObtDiscoveryHandler");
                    String deviceId = OCUuidUtil.uuidToString(uuid);
                    System.out.println("Discovered owned device: "+ deviceId);
                    System.out.println("\nDiscovered owned device: "+ deviceId + " at:");
                    while (endpoints != null) {
                        
                        String endpointStr = OCEndpointUtil.toString(endpoints);
                        System.out.println(endpointStr);
                        endpoints = endpoints.getNext();
                    }
                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
                        discoverOwnedDevicesHandlerExecuted.countDown();
                    }
                }
            }));
            assertTrue(discoverOwnedDevicesHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));

        } catch (InterruptedException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
