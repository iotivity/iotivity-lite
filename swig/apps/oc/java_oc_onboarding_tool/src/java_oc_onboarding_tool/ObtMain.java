package java_oc_onboarding_tool;

import java.util.Collections;
import java.util.InputMismatchException;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.Set;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ObtMain {

    /* user input Scanner */
    private static Scanner scanner = new Scanner(System.in);

    /* Constants */
    private static final int MAX_NUM_RESOURCES = 100;
    private static final int MAX_NUM_RT = 50;

    /* Sets containing discovered owned and un-owned devices */
    static Set<OCUuid> unownedDevices = Collections.synchronizedSet(new LinkedHashSet<OCUuid>());
    static Set<OCUuid> ownedDevices = Collections.synchronizedSet(new LinkedHashSet<OCUuid>());

    /* Callback handlers */
    private static UnownedDeviceHandler unownedDeviceHandler = new UnownedDeviceHandler();
    private static OwnedDeviceHandler ownedDeviceHandler = new OwnedDeviceHandler();
    private static JustWorksHandler justWorksHandler = new JustWorksHandler();
    private static GenerateRandomPinHandler generateRandomPinHandler = new GenerateRandomPinHandler();
    private static OtmRandomPinHandler otmRandomPinHandler = new OtmRandomPinHandler();
    private static ProvisionCredentialsHandler provisionCredentialsHandler = new ProvisionCredentialsHandler();
    private static ResetDeviceHandler resetDeviceHandler = new ResetDeviceHandler();
    private static ProvisionAce2Handler provisionAce2Handler = new ProvisionAce2Handler();

    private static boolean quit;
    private static OcObt obt;
    private static OcPlatform obtPlatform = OcPlatform.getInstance();
    private static Thread mainThread = Thread.currentThread();

    private static Thread shutdownHook = new Thread() {
        public void run() {
            quit = true;
            System.out.println("Calling platform shutdown.");
            obtPlatform.systemShutdown();
            obt.shutdown();
            scanner.close();
            mainThread.interrupt();
        }
    };

    private static void displayMenu() {
        StringBuilder menu = new StringBuilder();
        menu.append("\n################################################\n");
        menu.append("OCF 2.0 Onboarding Tool\n");
        menu.append("################################################\n");
        menu.append("[0] Display this menu\n");
        menu.append("------------------------------------------------\n");
        menu.append("[1] Discover un-owned devices\n");
        menu.append("[2] Discover owned devices\n");
        menu.append("------------------------------------------------\n");
        menu.append("[3] Just-Works Ownership Transfer Method\n");
        menu.append("[4] Request Random PIN from device for OTM\n");
        menu.append("[5] Random PIN Ownership Transfer Method\n");
        menu.append("[6] Provision pair-wise credentials\n");
        menu.append("[7] Provision ACE2\n");
        menu.append("------------------------------------------------\n");
        menu.append("[8] RESET device\n");
        menu.append("[9] RESET OBT\n");
        menu.append("------------------------------------------------\n");
        menu.append("[10] Exit\n");
        menu.append("################################################\n");
        menu.append("\nSelect option: ");
        System.out.print(menu);
    }

    private static void discoverUnownedDevices() {
        System.out.println("Discovering un-owned devices");
        if (obt.discoverUnownedDevices(unownedDeviceHandler) < 0) {
            System.err.println("ERROR discovering un-owned Devices.");
        }
    }

    private static void discoverOwnedDevices() {
        if (obt.discoverOwnedDevices(ownedDeviceHandler) < 0) {
            System.err.println("ERROR discovering owned Devices.");
        }
    }

    private static void otmJustWorks() {
        if (unownedDevices.isEmpty()) {
            System.out.println("\nPlease Re-discover Unowned devices");
            return;
        }

        int i = 0;

        StringBuilder unownedDevicesMenu = new StringBuilder();
        unownedDevicesMenu.append("\nUnowned Devices:\n");
        OCUuid[] uds = unownedDevices.toArray(new OCUuid[unownedDevices.size()]);
        for (OCUuid ud : uds) {
            unownedDevicesMenu.append("[" + i + "]: " + OCUuidUtil.uuidToString(ud) + "\n");
            i++;
        }
        unownedDevicesMenu.append("\n\nSelect device: ");
        System.out.print(unownedDevicesMenu);

        int userInput = scanner.nextInt();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        int ret = obt.performJustWorksOtm(uds[userInput], justWorksHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to perform ownership transfer");
        } else {
            System.out.println("\nERROR issuing request to perform ownership transfer");
        }

        /*
         * Having issued an OTM request, remove this item from the unowned
         * device list
         */
        unownedDevices.remove(uds[userInput]);
    }

    private static void requestRandomPin() {
        if (unownedDevices.isEmpty()) {
            System.out.println("\nPlease Re-discover Unowned devices");
            return;
        }

        int i = 0;

        StringBuilder unownedDevicesMenu = new StringBuilder();
        unownedDevicesMenu.append("\nUnowned Devices:\n");
        OCUuid[] uds = unownedDevices.toArray(new OCUuid[unownedDevices.size()]);
        for (OCUuid ud : uds) {
            unownedDevicesMenu.append("[" + i + "]: " + OCUuidUtil.uuidToString(ud) + "\n");
            i++;
        }
        unownedDevicesMenu.append("\n\nSelect device: ");
        System.out.print(unownedDevicesMenu);

        int userInput = scanner.nextInt();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        int ret = obt.requestRandomPin(uds[userInput], generateRandomPinHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to generate a random pin");
        } else {
            System.out.println("\nERROR issuing request to generate a random pin");
        }
    }

    private static void otmRandomPin() {
        if (unownedDevices.isEmpty()) {
            System.out.println("\nPlease Re-discover Unowned devices");
            return;
        }

        int i = 0;

        StringBuilder unownedDevicesMenu = new StringBuilder();
        unownedDevicesMenu.append("\nUnowned Devices:\n");
        OCUuid[] uds = unownedDevices.toArray(new OCUuid[unownedDevices.size()]);
        for (OCUuid ud : uds) {
            unownedDevicesMenu.append("[" + i + "]: " + OCUuidUtil.uuidToString(ud) + "\n");
            i++;
        }
        unownedDevicesMenu.append("\n\nSelect device: ");
        System.out.print(unownedDevicesMenu);

        int userInput = scanner.nextInt();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        System.out.print("Enter Random PIN: ");
        String pin = scanner.next();
        // max string length for pin is 24 characters
        if (pin.length() > 24) {
            pin = pin.substring(0, 24);
        }

        int ret = obt.performRandomPinOtm(uds[userInput], pin, otmRandomPinHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to perform Random PIN OTM");
        } else {
            System.out.println("\nERROR issuing request to perform Random PIN OTM");
        }

        /*
         * Having issued an OTM request, remove this item from the unowned
         * device list
         */
        unownedDevices.remove(uds[userInput]);
    }

    private static void provisionCredentials() {
        if (ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        int i = 0;

        StringBuilder ownedDevicesMenu = new StringBuilder();
        ownedDevicesMenu.append("\nMy Devices:\n");
        OCUuid[] ods = ownedDevices.toArray(new OCUuid[ownedDevices.size()]);
        for (OCUuid od : ods) {
            ownedDevicesMenu.append("[" + i + "]: " + OCUuidUtil.uuidToString(od) + "\n");
            i++;
        }
        ownedDevicesMenu.append("\nSelect device 1: ");
        System.out.print(ownedDevicesMenu);
        int userInput1 = scanner.nextInt();
        if (userInput1 < 0 || userInput1 >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        System.out.print("\nSelect device 2: ");
        int userInput2 = scanner.nextInt();
        if (userInput2 < 0 || userInput2 >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        int ret = obt.provisionPairwiseCredentials(ods[userInput1], ods[userInput2], provisionCredentialsHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to provision credentials");
        } else {
            System.out.println("\nERROR issuing request to provision credentials");
        }
    }

    private static void provisionAce2() {
        if (ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        String[] connTypes = new String[] { "anon-clear", "auth-crypt" };
        int num_resources = 0;

        System.out.println("\nProvision ACL2\nMy Devices:");

        int i = 0;

        StringBuilder ownedDevicesMenu = new StringBuilder();
        ownedDevicesMenu.append("\nMy Devices:\n");
        OCUuid[] ods = ownedDevices.toArray(new OCUuid[ownedDevices.size()]);
        for (OCUuid od : ods) {
            ownedDevicesMenu.append("[" + i + "]: " + OCUuidUtil.uuidToString(od) + "\n");
            i++;
        }

        if (i == 0) {
            System.out.println("\nNo devices to provision... Please Re-Discover Owned devices.");
            return;
        }

        ownedDevicesMenu.append("\n\nSelect device for provisioning: ");
        System.out.print(ownedDevicesMenu);
        int dev = scanner.nextInt();
        if (dev < 0 || dev >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        StringBuilder subjectsMenu = new StringBuilder();
        subjectsMenu.append("\nSubjects:\n");
        subjectsMenu.append("[0]: " + connTypes[0] + "\n");
        subjectsMenu.append("[1]: " + connTypes[1] + "\n");
        i = 0;
        for (OCUuid od : ods) {
            subjectsMenu.append("[" + (i + 2) + "]: " + OCUuidUtil.uuidToString(od) + "\n");
            i++;
        }
        subjectsMenu.append("\nSelect subject: ");
        System.out.print(subjectsMenu);
        int sub = scanner.nextInt();

        if (sub >= (i + 2)) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        OcSecurityAce ace = null;
        if (sub > 1) {
            ace = new OcSubjectSecurityAce(ods[sub - 2]);
        } else {
            if (sub == 0) {
                ace = new OcAnonSecurityAce();
            } else {
                ace = new OcAuthSecurityAce();
            }
        }

        if (ace == null) {
            System.out.println("\nERROR: Could not create ACE");
            return;
        }

        while (num_resources <= 0 || num_resources > MAX_NUM_RESOURCES) {
            if (num_resources != 0) {
                System.out.println("\n\nERROR: Enter valid number\n");
            }
            System.out.print("\nEnter number of resources in this ACE: ");
            num_resources = scanner.nextInt();
        }

        System.out.println("\nResource properties");
        i = 0;
        while (i < num_resources) {
            OcAceResource res = new OcAceResource(ace);

            if (res == null) {
                System.out.println("\nERROR: Could not allocate new resource for ACE");
                return;
            }

            System.out.print("Have resource href? [0-No, 1-Yes]: ");
            int c = scanner.nextInt();
            if (c == 1) {
                System.out.print("Enter resource href (eg. /a/light): ");
                String href;
                // max string length in C is 64 characters including
                // the nul character, so useable lenght is 63
                href = scanner.next();
                if (href.length() > 63) {
                    href = href.substring(0, 63);
                }

                res.setHref(href);
                res.setWildcard(OCAceWildcard.OC_ACE_NO_WC);
            } else {
                System.out.print("\nSet wildcard resource? [0-No, 1-Yes]: ");
                c = scanner.nextInt();
                if (c == 1) {
                    StringBuilder wildcardMenu = new StringBuilder();
                    wildcardMenu.append("[1]: All NCRs '*'\n");
                    wildcardMenu.append("[2]: All NCRs with >=1   secured endpoint '+'\n");
                    wildcardMenu.append("[3]: All NCRs with >=1 unsecured endpoint '-'\n");
                    wildcardMenu.append("\nSelect wildcard resource: ");
                    System.out.print(wildcardMenu);
                    c = scanner.nextInt();
                    switch (c) {
                    case 1:
                        res.setWildcard(OCAceWildcard.OC_ACE_WC_ALL);
                        break;
                    case 2:
                        res.setWildcard(OCAceWildcard.OC_ACE_WC_ALL_SECURED);
                        break;
                    case 3:
                        res.setWildcard(OCAceWildcard.OC_ACE_WC_ALL_PUBLIC);
                        break;
                    default:
                        break;
                    }
                }
            }

            System.out.print("Enter number of resource types [0-None]: ");
            c = scanner.nextInt();
            if (c > 0 && c <= MAX_NUM_RT) {
                res.setNumberOfResourceTypes(c);

                int j = 0;
                while (j < c) {
                    System.out.print("Enter resource type [" + (j + 1) + "]: ");
                    String rt = scanner.next();
                    if (rt.length() > 127) {
                        rt = rt.substring(0, 127);
                    }
                    res.bindResourceType(rt);
                    j++;
                }
            }
            System.out.print("Enter number of interfaces [0-None]: ");
            c = scanner.nextInt();
            if (c > 0 && c <= 7) {
                int j = 0;
                while (j < c) {
                    int k;
                    StringBuilder interfacesMenu = new StringBuilder();
                    interfacesMenu.append("\n[1]: oic.if.baseline\n");
                    interfacesMenu.append("[2]: oic.if.ll\n");
                    interfacesMenu.append("[3]: oic.if.b\n");
                    interfacesMenu.append("[4]: oic.if.r\n");
                    interfacesMenu.append("[5]: oic.if.rw\n");
                    interfacesMenu.append("[6]: oic.if.a\n");
                    interfacesMenu.append("[7]: oic.if.s\n");
                    interfacesMenu.append("\nSelect interface [" + (j + 1) + "]: ");
                    System.out.print(interfacesMenu);
                    k = scanner.nextInt();
                    switch (k) {
                    case 1:
                        res.bindInterface(OCInterfaceMask.BASELINE);
                        break;
                    case 2:
                        res.bindInterface(OCInterfaceMask.LL);
                        break;
                    case 3:
                        res.bindInterface(OCInterfaceMask.B);
                        break;
                    case 4:
                        res.bindInterface(OCInterfaceMask.R);
                        break;
                    case 5:
                        res.bindInterface(OCInterfaceMask.RW);
                        break;
                    case 6:
                        res.bindInterface(OCInterfaceMask.A);
                        break;
                    case 7:
                        res.bindInterface(OCInterfaceMask.S);
                        break;
                    default:
                        break;
                    }
                    j++;
                }
            } else if (c < 0 || c > 7) {
                System.out.println("\nWARNING: Invalid number of interfaces... skipping interface selection");
            }
            i++;
        }

        System.out.println("\nSet ACE2 permissions");
        System.out.print("CREATE [0-No, 1-Yes]: ");
        int c = scanner.nextInt();
        if (c == 1) {
            ace.addPermission(OCAcePermissionsMask.CREATE);
        }
        System.out.print("RETRIEVE [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            ace.addPermission(OCAcePermissionsMask.RETRIEVE);
        }
        System.out.print("UPDATE [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            ace.addPermission(OCAcePermissionsMask.UPDATE);
        }
        System.out.print("DELETE [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            ace.addPermission(OCAcePermissionsMask.DELETE);
        }
        System.out.print("NOTIFY [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            ace.addPermission(OCAcePermissionsMask.NOTIFY);
        }

        int ret = obt.provisionAce(ods[dev], ace, provisionAce2Handler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to provision ACE");
        } else {
            System.out.println("\nERROR issuing request to provision ACE");
        }
    }

    private static void resetDevice() {
        if (ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        int i = 0;

        StringBuilder ownedDevicesMenu = new StringBuilder();
        ownedDevicesMenu.append("\nMy Devices:\n");
        OCUuid[] ods = ownedDevices.toArray(new OCUuid[ownedDevices.size()]);
        for (OCUuid od : ods) {
            ownedDevicesMenu.append("[" + i + "]: " + OCUuidUtil.uuidToString(od) + "\n");
            i++;
        }
        ownedDevicesMenu.append("\nSelect device : ");
        System.out.print(ownedDevicesMenu);

        int userInput = scanner.nextInt();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        int ret = obt.deviceHardReset(ods[userInput], resetDeviceHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to perform hard RESET");
        } else {
            System.out.println("\nERROR issuing request to perform hard RESET");
        }
    }

    public static void resetOBT() {
        OCMain.reset();
        obt.shutdown();
        ownedDevices.clear();
        unownedDevices.clear();
        obt = new OcObt();
    }
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String creds_path = "./onboarding_tool_creds/";
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        ObtInitHandler obtHandler = new ObtInitHandler(obtPlatform);
        obtPlatform.systemInit(obtHandler);
        obt = new OcObt();

        while (!quit) {
            displayMenu();
            int userInput = 0;
            try {
                userInput = scanner.nextInt();
            } catch (InputMismatchException e) {
                System.out.println("Invalid Input.");
                userInput = 0;
            }
            switch (userInput) {
            case 0:
                continue;
            case 1:
                discoverUnownedDevices();
                break;
            case 2:
                discoverOwnedDevices();
                break;
            case 3:
                otmJustWorks();
                break;
            case 4:
                requestRandomPin();
                break;
            case 5:
                otmRandomPin();
                break;
            case 6:
                provisionCredentials();
                break;
            case 7:
                provisionAce2();
                break;
            case 8:
                resetDevice();
                break;
            case 9:
                resetOBT();
                break;
            case 10:
                quit = true;
                break;
            default:
                break;
            }
        }

        obtPlatform.systemShutdown();
        obt.shutdown();
        System.exit(0);
    }
}
