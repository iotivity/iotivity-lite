package java_oc_dummy_bridge;

import java.util.InputMismatchException;
import java.util.Scanner;

import org.iotivity.*;
import org.iotivity.oc.*;

public class DummyBridge {
    /* user input Scanner */
    private static Scanner scanner = new Scanner(System.in);

    public static DummyVirtualLight[] virtualLights = {
            new DummyVirtualLight("Light 1", "1b32e152-3756-4fb6-b3f2-d8db7aafe39f",
                    "ABC", true, false, false),
            new DummyVirtualLight("Light 2", "f959f6fd-8d08-4766-849b-74c3eec5e041",
                    "ABC", false, false, false),
            new DummyVirtualLight("Light 3", "686ef93d-36e0-47fc-8316-fbd7045e850a",
                    "ABC", true, false, false),
            new DummyVirtualLight("Light 4", "02feb15a-bf94-4f33-9794-adfb25c7bc60",
                    "XYZ", false, false, false),
            new DummyVirtualLight("Light 5", "e2f0109f-ef7d-496a-9676-d3d87b38e52f",
                    "XYZ", true, false, false) };

    public static boolean displayAsciiLightsUI;

    static private boolean quit;
    static private OcPlatform platform = OcPlatform.getInstance();
    static private Thread mainThread = Thread.currentThread();
    static private OcBridge bridge;

    static private Thread shutdownHook = new Thread() {
        public void run() {
            quit = true;
            System.out.println("Calling platform shutdown.");
            platform.systemShutdown();
            scanner.close();
            mainThread.interrupt();
        }
    };

    private static int getIntUserInput() {
        while (!scanner.hasNextInt()) {
            System.out.println("Invalid input. Integer expected.");
            scanner.nextLine();
        }
        return scanner.nextInt();
    }

    static void printAsciiLightsUI() {
        StringBuilder lightUI = new StringBuilder();
        // This will build a row of ASCII art lights representing each virtual light
        //  _   _
        // (*) ( )
        //  #   #
        // ON  OFF
        //
        // top of ASCII light
        lightUI.append("\n");
        for (int i = 0; i < virtualLights.length; i++) {
            if (virtualLights[i].isDiscovered()) {
                lightUI.append("  _  ");
            } else
                lightUI.append("     ");
        }
        lightUI.append("\n");
        // middle of ASCII light
        for (int i = 0; i < virtualLights.length; i++) {
            if (virtualLights[i].isDiscovered()) {
                if (virtualLights[i].isOn()) {
                    lightUI.append(" (*) ");
                } else {
                    lightUI.append(" ( ) ");
                }
            } else
                lightUI.append("     ");
        }
        lightUI.append("\n");
        // bottom of ASCII light
        for (int i = 0; i < virtualLights.length; i++) {
            if (virtualLights[i].isDiscovered()) {
                lightUI.append("  #  ");
            } else
                lightUI.append("     ");
        }
        lightUI.append("\n");
        for (int i = 0; i < virtualLights.length; i++) {
            if (virtualLights[i].isDiscovered()) {
                if (virtualLights[i].isOn()) {
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
//        menu.append("[8] Reset Device\n");
        menu.append("-----------------------------------------------\n");
        menu.append("[99] Exit\n");
        menu.append("################################################\n");
        menu.append("Select option: \n");
        System.out.print(menu);
    }

    public static void registerBinarySwitchResource(DummyVirtualLight light) {
        String[] resourceTypes = new String[] { "oic.r.switch.binary" };
        int[] interfaceMasks = new int[] { OCInterfaceMask.A };

        OcResource resource = new OcResource(light, light.getName(), light.getUri(), resourceTypes, interfaceMasks);
        resource.setDefaultInterfaceMask(OCInterfaceMask.A);
        resource.setDiscoverable(true);
        resource.setObservable(true);
        resource.setGetRequestHandler(new SwitchGetHandler(light));
        resource.setPutRequestHandler(new SwitchPutHandler(light));
        resource.setPostRequestHandler(new SwitchPostHandler(light));
        light.addResource(resource);
    }

    public static void pollForDiscoveredDevices() {
        for (int i = 0; i < virtualLights.length; i++) {
            if (virtualLights[i].isDiscovered() && !virtualLights[i].isAddedToBridge()) {
                System.out.println("Adding " + virtualLights[i].getName() + " to bridge");
                int retValue = bridge.addVirtualDevice(virtualLights[i]);
                if (retValue > 0) {
                    registerBinarySwitchResource(virtualLights[i]);
                    virtualLights[i].setImmutableDeviceId(OCUuidUtil.stringToUuid(virtualLights[i].getUuid()));
                }
                virtualLights[i].setAddedToBridge(true);
            }
        }
    }

    public static void disconnectLight(int index) {
        virtualLights[index].setDiscovered(false);
        virtualLights[index].setAddedToBridge(false);
        if (bridge.removeVirtualDevice(virtualLights[index]) == 0) {
            System.out.println(virtualLights[index].getName() + " removed from the bridge.");
        } else {
            System.out.println("FAILED to remove " + virtualLights[index].getName() + " from the bridge.");
        }
        if (bridge.deleteVirtualDevice(virtualLights[index]) == 0) {
            System.out.println(virtualLights[index].getName() + " deleted from the bridge.");
        } else {
            System.out.println("FAILED to delete " + virtualLights[index].getName() + " from the bridge.");
        }
    }

    public static void discoverLight(int index) {
        virtualLights[index].setDiscovered(!virtualLights[index].isDiscovered());
        if (virtualLights[index].isDiscovered()) {
            System.out.println("Discover Light: " + virtualLights[index].getName());
            pollForDiscoveredDevices();
        } else {
            System.out.println("Disconnect Light: " + virtualLights[index].getName());
            disconnectLight(index);
        }
    }

    public static void displaySummary() {
        for (int i = 0; i < virtualLights.length; i++) {
            StringBuilder summary = new StringBuilder();
            summary.append(virtualLights[i].getName() + " :\n");
            summary.append("\tVirtual Device Id: " + virtualLights[i].getUuid() + "\n");
            summary.append("\tEco Name: " + virtualLights[i].getEcoSystemName() + "\n");
            summary.append("\tLight switch is: " + (virtualLights[i].isOn() ? "ON" : "OFF") + "\n");
            summary.append("\tAdded to bridge: " + (virtualLights[i].isDiscovered() ? "" : "not") + " discovered\n");
            summary.append("\tOcf Device Id: ");
            if (virtualLights[i].isAddedToBridge()) {
                OCUuid di = virtualLights[i].getId();
                summary.append(OCUuidUtil.uuidToString(di) + "\n");
            } else {
                summary.append("N/A\n");
            }
            System.out.println(summary);
        }
        System.out.println("DisplaySummary");
    }

    public static void resetDevice() {
        System.out.println("ResetDevice -- not implemented");
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

        InitHandler initHandler = new InitHandler(platform);
        platform.systemInit(initHandler);
        bridge = new OcBridge("Dummy Bridge", "ocf.2.0.0", "ocf.res.1.0.0,ocf.sh.1.0.0", new OCAddDeviceHandler() {
            public void handler() {
                System.out.println("inside OcBridge.OCAddDeviceHandler.handler()");
            }
        });

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
        platform.systemShutdown();
        System.exit(0);
    }
}
