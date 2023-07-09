package java_dummy_bridge;

import java.util.InputMismatchException;
import java.util.Scanner;

import org.iotivity.OCBridge;
import org.iotivity.OCCoreRes;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCMethod;
import org.iotivity.OCResource;
import org.iotivity.OCStorage;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidUtil;

public class DummyBridgeMain {
    /* user input Scanner */
    private static Scanner scanner = new Scanner(System.in);

    /* Constants */
    public static VirtualLight virtualLights[] = {
            new VirtualLight("Light 1", "1b32e152-3756-4fb6-b3f2-d8db7aafe39f", "ABC", true, false, false),
            new VirtualLight("Light 2", "f959f6fd-8d08-4766-849b-74c3eec5e041", "ABC", false, false, false),
            new VirtualLight("Light 3", "686ef93d-36e0-47fc-8316-fbd7045e850a", "ABC", true, false, false),
            new VirtualLight("Light 4", "02feb15a-bf94-4f33-9794-adfb25c7bc60", "XYZ", false, false, false),
            new VirtualLight("Light 5", "e2f0109f-ef7d-496a-9676-d3d87b38e52f", "XYZ", true, false, false)
    };

    public static boolean displayAsciiLightsUI = false;

    static private boolean quit;
    static private Thread mainThread;
    static private Thread shutdownHook = new Thread() {
        public void run() {
            quit = true;
            System.out.println("Calling mainShutdown.");
            OCMain.mainShutdown();
            scanner.close();
            mainThread.interrupt();
        }
    };

    private static int getIntUserInput() {
        while(!scanner.hasNextInt()) {
            System.out.println("Invalid input. Integer expected.");
            scanner.nextLine();
        }
        return scanner.nextInt();
    }

    public static void printAsciiLightsUI()
    {
        StringBuilder lightUI = new StringBuilder();
        // This will build a row of ASCII art lights representing each virtual light
        //  _   _
        // (*) ( )
        //  #   #
        // ON  OFF
        //
        // top of ASCII light
        lightUI.append("\n");
        for (int i = 0; i < virtualLights.length; i++)
        {
            if (virtualLights[i].discovered) {
                lightUI.append("  _  ");
            } else
                lightUI.append("     ");
        }
        lightUI.append("\n");
        // middle of ASCII light
        for (int i = 0; i < virtualLights.length; i++)
        {
            if (virtualLights[i].discovered) {
                if (virtualLights[i].on) {
                    lightUI.append(" (*) ");
                } else {
                    lightUI.append(" ( ) ");
                }
            } else
                lightUI.append("     ");
        }
        lightUI.append("\n");
        // bottom of ASCII light
        for (int i = 0; i < virtualLights.length; i++)
        {
            if (virtualLights[i].discovered) {
                lightUI.append("  #  ");
            } else
                lightUI.append("     ");
        }
        lightUI.append("\n");
        for (int i = 0; i < virtualLights.length; i++)
        {
            if (virtualLights[i].discovered) {
                if (virtualLights[i].on) {
                    lightUI.append(" ON  ");
                } else {
                    lightUI.append(" OFF ");
                }
            } else
                lightUI.append(" N/A ");
        }
        lightUI.append("\n");
        System.out.print(lightUI);
    }
    public static void displayMenu() {
        if (displayAsciiLightsUI) {
            printAsciiLightsUI();
        }
        StringBuilder menu = new StringBuilder();
        menu.append("################################################\n");
        menu.append("Dummy Bridge\n");
        menu.append("################################################\n");
        menu.append("[0] Display this menu\n");
        menu.append("-----------------------------------------------\n");
        menu.append("[1] Simulate discovery of 'Light 1'\n");
        menu.append("[2] Simulate discovery of 'Light 2'\n");
        menu.append("[3] Simulate discovery of 'Light 3'\n");
        menu.append("[4] Simulate discovery of 'Light 4'\n");
        menu.append("[5] Simulate discovery of 'Light 5'\n");
        menu.append("   Select simulate discovery of any device again\n");
        menu.append("   to simulate that device being disconnected.\n");
        menu.append("-----------------------------------------------\n");
        menu.append("[6] Display summary of dummy bridge.\n");
        menu.append("[7] Enable/Disable ASCII light bulb UI.\n");
        menu.append("    A representation of the bridged lights\n");
        menu.append("    using ASCII art.\n");
        menu.append("[8] Reset Device\n");
        menu.append("-----------------------------------------------\n");
        menu.append("[99] Exit\n");
        menu.append("################################################\n");
        menu.append("Select option: \n");
        System.out.print(menu);
    }

    public static void registerBinaryswitchResource(String name, String uri, long device_index, VirtualLight light)
    {
        OCResource r = OCMain.newResource(name, uri, (short)1, device_index);
        OCMain.resourceBindResourceType(r, "oic.r.switch.binary");
        OCMain.resourceBindResourceInterface(r, OCInterfaceMask.A);
        OCMain.resourceSetDefaultInterface(r, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(r, true);
        OCMain.resourceSetRequestHandler(r, OCMethod.OC_GET, new SwitchGetHandler(light));
        OCMain.resourceSetRequestHandler(r, OCMethod.OC_POST, new SwitchPostHandler(light));
        OCMain.resourceSetRequestHandler(r, OCMethod.OC_PUT, new SwitchPutHandler(light));
        
    }
    
    public static void pollForDiscoveredDevices()
    {
        for (int i =0; i < virtualLights.length; i++)
        {
            if (virtualLights[i].discovered && !virtualLights[i].addedToBridge) {
                System.out.println("Adding " + virtualLights[i].deviceName + " to bridge");
                long virtualDeviceIndex = OCBridge.addVirtualDevice(virtualLights[i].uuid.getBytes(),
                                                                    virtualLights[i].ecoSystem,
                                                                    "/oic/d", "oic.d.light",
                                                                    virtualLights[i].deviceName,
                                                                    "ocf.1.0.0", "ocf.res.1.0.0");
                if (virtualDeviceIndex != 0) {
                    registerBinaryswitchResource(virtualLights[i].deviceName,
                                                 "/bridge/light/switch",
                                                 virtualDeviceIndex, virtualLights[i]);
                    OCMain.setImmutableDeviceIdentifier(virtualDeviceIndex, OCUuidUtil.stringToUuid(virtualLights[i].uuid));
                }
                virtualLights[i].addedToBridge = true;
            }
        }
    }
    
    public static void disconnectLight(int index)
    {
        virtualLights[index].discovered = false;
        virtualLights[index].addedToBridge = false;
        long device = OCBridge.getVirtualDeviceIndex(virtualLights[index].uuid.getBytes(), virtualLights[index].ecoSystem);
        if (device != 0)
        {
            if (OCBridge.removeVirtualDevice(device) == 0) {
                System.out.println(virtualLights[index].deviceName  + " removed from the bridge.");
            } else {
                System.out.println("FAILED to remove " + virtualLights[index].deviceName  + " from the bridge.");
            }
        } else {
            System.out.println("FAILED to find virtual light to remove.");
        }
        
    }
    public static void discoverLight(int index)
    {
        virtualLights[index].discovered = !virtualLights[index].discovered;
        if (virtualLights[index].discovered) {
            System.out.println("Discover Light: " + virtualLights[index].deviceName);
            pollForDiscoveredDevices();
        } else {
            System.out.println("Disconnect Light: " + virtualLights[index].deviceName);
            disconnectLight(index);
        }
        
    }
    
    public static void displaySummary()
    {
        for (int i = 0 ; i < virtualLights.length; i++)
        {
            StringBuilder summary = new StringBuilder();
            summary.append(virtualLights[i].deviceName + " :\n");
            summary.append("\tVirtual Device ID: " + virtualLights[i].uuid + "\n");
            summary.append("\tEconame: " + virtualLights[i].ecoSystem + "\n");
            summary.append("\tLight switch is: ");
            if (virtualLights[i].on) {
                summary.append("ON\n");
            } else {
                summary.append("OFF\n");
            }
            summary.append("\tAdded to bridge: ");
            if(virtualLights[i].discovered) {
                summary.append("discovered\n");
            } else {
                summary.append("not discovered\n");
            }
            summary.append("\tOCF Device ID: ");
            if(virtualLights[i].addedToBridge) {
                long device = OCBridge.getVirtualDeviceIndex(virtualLights[i].uuid.getBytes(), virtualLights[i].ecoSystem);
                OCUuid di = OCCoreRes.getDeviceId(device);
                summary.append(OCUuidUtil.uuidToString(di) + "\n");
            } else {
                summary.append("N/A\n");
            }
            System.out.println(summary);
        }
        System.out.println("DisplaySummary");
    }
    
    public static void resetDevice()
    {
        System.out.println("ResetDevice");
    }
    
    public static void main(String[] args) {
        quit = false;
        mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String creds_path = "./dummy_bridge_creds/";
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        InitHandler initHandler = new InitHandler();
        int init_ret = OCMain.mainInit(initHandler);
        if (init_ret < 0) {
            System.exit(init_ret);
        }

        while (!quit) {
            displayMenu();
            int userInput = 0;
            try {
                userInput = getIntUserInput();
            } catch (InputMismatchException e) {
                System.out.println("Invalid Input.");
                userInput = 0;
            }
            switch (userInput) {
            case 0:
                continue;
            case 1:
                discoverLight(0);
                break;
            case 2:
                discoverLight(1);
                break;
            case 3:
                discoverLight(2);
                break;
            case 4:
                discoverLight(3);
                break;
            case 5:
                discoverLight(4);
                break;
            case 6:
                displaySummary();
                break;
            case 7:
                displayAsciiLightsUI = !displayAsciiLightsUI;
                break;
            case 8:
                resetDevice();
                break;
            case 99:
                quit = true;
                break;
            default:
                break;
            }
        }
        OCMain.mainShutdown();
        System.exit(0);
    }
}
