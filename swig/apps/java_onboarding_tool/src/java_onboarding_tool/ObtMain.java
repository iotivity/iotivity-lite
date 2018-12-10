package java_onboarding_tool;

import java.util.InputMismatchException;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.iotivity.OCAceConnectionType;
import org.iotivity.OCAcePermissionsMask;
import org.iotivity.OCAceResource;
import org.iotivity.OCAceWildcard;
import org.iotivity.OCClock;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCObt;
import org.iotivity.OCSecurityAce;
import org.iotivity.OCStorage;
import org.iotivity.OCUuidUtil;
import org.iotivity.OCUuid;

import java_onboarding_tool.UnownedDeviceHandler;

public class ObtMain {
    public final static Lock appSyncLock = new ReentrantLock();
    public final static Lock lock = new ReentrantLock();
    public static Condition cv = lock.newCondition();

    public static final long NANOS_PER_SECOND = 1000000000; // 1.e09
    public static final long CLOCK_TICKS_PER_SECOND = OCClock.OC_CLOCK_SECOND;

    static private boolean quit;
    static private Thread mainThread;
    static private Thread shutdownHook = new Thread() {
        public void run() {
            quit = true;
            System.out.println("Calling main_shutdown.");
            OCMain.mainShutdown();
            mainThread.interrupt();
        }
    };

    static private Thread ocfEventThread = new Thread() {
        public void run() {
            String osName = System.getProperty("os.name");
            boolean isLinux = (osName != null) && osName.toLowerCase().contains("linux");
            System.out.println("OS Name = " + osName + ", isLinux = " + isLinux);

            while (!quit) {
                long next_event = OCMain.mainPoll();
                lock.lock();
                try {
                    if (next_event == 0) {
                        System.out.println("Calling cv.await");
                        cv.await();
                    } else {
                        if (isLinux) {
                            // For Linux next_event is absolute time.
                            // Decrement next_event by the current time to get the nanoseconds to wait.
                            long next_event_secs = (next_event / CLOCK_TICKS_PER_SECOND);
                            long next_event_nanos = (next_event % CLOCK_TICKS_PER_SECOND) * (NANOS_PER_SECOND / CLOCK_TICKS_PER_SECOND);

                            long now = OCClock.clockTime();
                            long now_secs = (now / CLOCK_TICKS_PER_SECOND);
                            long now_nanos = (now % CLOCK_TICKS_PER_SECOND) * (NANOS_PER_SECOND / CLOCK_TICKS_PER_SECOND);

                            long timeToWait = ((next_event_secs * NANOS_PER_SECOND) + next_event_nanos) -
                                    ((now_secs * NANOS_PER_SECOND) + now_nanos);
                            //System.out.println("Calling cv.awaitNanos " + timeToWait);
                            cv.awaitNanos(timeToWait);
                        } else {
                            //System.out.println("Calling cv.awaitNanos " + next_event);
                            long now = OCClock.clockTime();
                            cv.awaitNanos((next_event - now) * 1000000 / OCClock.OC_CLOCK_SECOND);
                        }
                    }
                } catch (InterruptedException e) {
                    System.out.println(e);
                } finally {
                    lock.unlock();
                }
            }
        }
    };

    public static Set<OCUuid> unownedDevices = new LinkedHashSet<OCUuid>();
    public static Set<OCUuid> ownedDevices = new LinkedHashSet<OCUuid>();

    private static UnownedDeviceHandler unownedDeviceHandler = new UnownedDeviceHandler();
    private static OwnedDeviceHandler ownedDeviceHandler = new OwnedDeviceHandler();
    private static JustWorksHandler justWorksHandler = new JustWorksHandler();
    private static ProvisionCredentialsHandler provisionCredentialsHandler = new ProvisionCredentialsHandler();
    private static ResetDeviceHandler resetDeviceHandler = new ResetDeviceHandler();
    private static ProvisionAce2Handler provisionAce2Handler = new ProvisionAce2Handler(); 

    private static final int MAX_NUM_RESOURCES = 100;
    private static final int MAX_NUM_RT = 50;

    public static void displayMenu()
    {
        System.out.println("\n################################################");
        System.out.println("OCF 1.3 Onboarding Tool");
        System.out.println("################################################");
        System.out.println("[0] Display this menu");
        System.out.println("------------------------------------------------");
        System.out.println("[1] Discover un-owned devices");
        System.out.println("[2] Discover owned devices");
        System.out.println("------------------------------------------------");
        System.out.println("[3] Take ownership of device (Just-works)");
        System.out.println("[4] Provision pair-wise credentials");
        System.out.println("[5] Provision ACE2");
        System.out.println("------------------------------------------------");
        System.out.println("[6] RESET device");
        System.out.println("------------------------------------------------");
        System.out.println("[9] Exit");
        System.out.println("################################################");
        System.out.print("\nSelect option: ");
    }

    private static void discoverUnownedDevices()
    {
        System.out.println("Discovering un-owned devices");
        appSyncLock.lock();
        if ( 0 > OCObt.discoverUnownedDevices(unownedDeviceHandler)) {
            System.err.println("ERROR discovering un-owned Devices.");
        }
        appSyncLock.unlock();
    }

    private static void discoverOwnedDevices()
    {
        appSyncLock.lock();
        if (0 > OCObt.discoverOwnedDevices(ownedDeviceHandler)) {
            System.err.println("ERROR discovering owned Devices.");
        }
        appSyncLock.unlock();
    }

    private static void takeOwnershipOfDevice() {
        if (unownedDevices.isEmpty()) {
            System.out.println("\nPlease Re-discover Unowned devices");
            return;
        }

        int i = 0;

        System.out.println("\nUnowned Devices:");
        OCUuid[] uds = unownedDevices.toArray(new OCUuid[unownedDevices.size()]);
        for(OCUuid ud : uds) {
            System.out.println("[" + i + "]: " + OCUuidUtil.uuidToString(ud));
            i++;
        }
        System.out.print("\n\nSelect device: ");
        Scanner scanner = new Scanner(System.in);
        int userInput = scanner.nextInt();
        scanner.close();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        appSyncLock.lock();

        int ret = OCObt.performJustWorksOtm(uds[userInput], justWorksHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to perform ownership transfer");
        } else {
            System.out.println("\nERROR issuing request to perform ownership transfer");
        }

        /* Having issued an OTM request, remove this item from the unowned device list
         */
        unownedDevices.remove(uds[userInput]);
        appSyncLock.unlock();
    }

    private static void provisionCredentials() {
        if(ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        int i = 0;

        System.out.println("\nMy Devices:");
        OCUuid[] ods = ownedDevices.toArray(new OCUuid[ownedDevices.size()]);
        for(OCUuid od : ods) {
            System.out.println("[" + i + "]: " + OCUuidUtil.uuidToString(od));
            i++;
        }
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nSelect device 1: ");
        int userInput1 = scanner.nextInt();
        if (userInput1 < 0 || userInput1 >= i) {
            System.out.println("ERROR: Invalid selection");
            scanner.close();
            return;
        }

        System.out.print("\nSelect device 2: ");
        int userInput2 = scanner.nextInt();
        scanner.close();
        if (userInput2 < 0 || userInput2 >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        appSyncLock.lock();
        int ret = OCObt.provisionPairwiseCredentials(ods[userInput1], ods[userInput2], provisionCredentialsHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to provision credentials");
        } else {
            System.out.println("\nERROR issuing request to provision credentials");
        }
        appSyncLock.unlock();
    }

    public static void provisionAce2() {
        if(ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        String[] connTypes = new String[]{ "anon-clear", "auth-crypt" };
        int num_resources = 0;

        System.out.println("\nProvision ACL2\nMy Devices:");

        int i = 0;

        System.out.println("\nMy Devices:");
        OCUuid[] ods = ownedDevices.toArray(new OCUuid[ownedDevices.size()]);
        for(OCUuid od : ods) {
            System.out.println("[" + i + "]: " + OCUuidUtil.uuidToString(od));
            i++;
        }


        if (i == 0) {
            System.out.println("\nNo devices to provision.. Please Re-Discover Owned devices.");
            return;
        }

        Scanner scanner = new Scanner(System.in);
        System.out.print("\n\nSelect device for provisioning: ");
        int dev = scanner.nextInt();
        if (dev < 0 || dev >= i) {
            System.out.println("ERROR: Invalid selection");
            scanner.close();
            return;
        }

        System.out.println("\nSubjects: ");
        System.out.println("[0]: " + connTypes[0]);
        System.out.println("[1]: " + connTypes[1]);
        i = 0;
        for(OCUuid od : ods) {
            System.out.println("[" + (i + 2) + "]: " + OCUuidUtil.uuidToString(od));
            i++;
        }
        System.out.print("\nSelect subject: ");
        int sub = scanner.nextInt();

        if (sub >= (i + 2)) {
            System.out.println("ERROR: Invalid selection");
            scanner.close();
            return;
        }

        OCSecurityAce ace = null;
        if (sub > 1) {
            ace = OCObt.newAceForSubject(ods[sub - 2]);
        } else {
            if (sub == 0) {
                ace = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_ANON_CLEAR);
            } else {
                ace = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_AUTH_CRYPT);
            }
        }

        if (ace == null) {
            System.out.println("\nERROR: Could not create ACE");
            scanner.close();
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
            OCAceResource res = OCObt.aceNewResource(ace);

            if (res == null) {
                System.out.println("\nERROR: Could not allocate new resource for ACE");
                OCObt.freeAce(ace);
                scanner.close();
                return;
            }

            System.out.print("Have resource href? [0-No, 1-Yes]: ");
            int c = scanner.nextInt();
            if (c == 1) {
                System.out.println("Enter resource href (eg. /a/light): ");
                String href;
                // max string length in C is 64 characters
                // removing then nul character that is 63
                href = scanner.next().substring(0, 63);

                OCObt.aceResourceSetHref(res, href);
                OCObt.aceResourceSetWc(res, OCAceWildcard.OC_ACE_NO_WC);
            } else {
                System.out.print("\nSet wildcard resource? [0-No, 1-Yes]: ");
                c = scanner.nextInt();
                if (c == 1) {
                    System.out.println("[1]: All resources");
                    System.out.println("[2]: All discoverable resources");
                    System.out.println("[3]: All non-discoverable resources");
                    System.out.print("\nSelect wildcard resource: ");
                    c = scanner.nextInt();
                    switch (c) {
                    case 1:
                        OCObt.aceResourceSetWc(res, OCAceWildcard.OC_ACE_WC_ALL);
                        break;
                    case 2:
                        OCObt.aceResourceSetWc(res, OCAceWildcard.OC_ACE_WC_ALL_DISCOVERABLE);
                        break;
                    case 3:
                        OCObt.aceResourceSetWc(res, OCAceWildcard.OC_ACE_WC_ALL_NON_DISCOVERABLE);
                        break;
                    default:
                        break;
                    }
                }
            }

            System.out.print("Enter number of resource types [0-None]: ");
            c = scanner.nextInt();
            if (c > 0 && c <= MAX_NUM_RT) {
                OCObt.aceResoruceSetNumRt(res, c);

                int j = 0;
                while (j < c) {
                    System.out.print("Enter resource type : " + j + 1);
                    String rt = scanner.next().substring(0, 127);
                    OCObt.aceResoruceBindRt(res, rt);
                    j++;
                }
            }
            System.out.print("Enter number of interfaces [0-None] : ");
            c = scanner.nextInt();
            if (c > 0 && c <= 7) {
                int j = 0;
                while (j < c) {
                    int k;
                    System.out.println("\n[1]: oic.if.baseline");
                    System.out.println("[2]: oic.if.ll");
                    System.out.println("[3]: oic.if.b");
                    System.out.println("[4]: oic.if.r");
                    System.out.println("[5]: oic.if.rw");
                    System.out.println("[6]: oic.if.a");
                    System.out.println("[7]: oic.if.s");
                    System.out.println("\nSelect interface [" + j + 1 + "]: ");
                    k = scanner.nextInt();
                    switch (k) {
                    case 1:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.BASELINE);
                        break;
                    case 2:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.LL);
                        break;
                    case 3:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.B);
                        break;
                    case 4:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.R);
                        break;
                    case 5:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.RW);
                        break;
                    case 6:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.A);
                        break;
                    case 7:
                        OCObt.aceResourceBindIf(res, OCInterfaceMask.S);
                        break;
                    default:
                        break;
                    }
                    j++;
                }
            } else if (c < 0 || c > 7) {
                System.out.println("\nWARNING: Invalid number of interfaces.."
                        + "           skipping interface selection");
            }
            i++;
        }

        System.out.println("\nSet ACE2 permissions");
        System.out.print("CREATE [0-No, 1-Yes]: ");
        int c = scanner.nextInt();
        if (c == 1) {
            OCObt.aceAddPermission(ace, OCAcePermissionsMask.CREATE);
        }
        System.out.print("RETRIEVE [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            OCObt.aceAddPermission(ace, OCAcePermissionsMask.RETRIEVE);
        }
        System.out.print("UPDATE [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            OCObt.aceAddPermission(ace, OCAcePermissionsMask.UPDATE);
        }
        System.out.print("DELETE [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            OCObt.aceAddPermission(ace, OCAcePermissionsMask.DELETE);
        }
        System.out.print("NOTIFY [0-No, 1-Yes]: ");
        c = scanner.nextInt();
        if (c == 1) {
            OCObt.aceAddPermission(ace, OCAcePermissionsMask.NOTIFY);
        }
        scanner.close();

        appSyncLock.lock();
        int ret =
                OCObt.provisionAce(ods[dev], ace, provisionAce2Handler);
        appSyncLock.unlock();
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to provision ACE");
        } else {
            System.out.println("\nERROR issuing request to provision ACE");
        }
    }

    public static void resetDevice() {
        if(ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        int i = 0;

        System.out.println("\nMy Devices:");
        OCUuid[] ods = ownedDevices.toArray(new OCUuid[ownedDevices.size()]);
        for(OCUuid od : ods) {
            System.out.println("[" + i + "]: " + OCUuidUtil.uuidToString(od));
            i++;
        }
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nSelect device : ");
        int userInput = scanner.nextInt();
        scanner.close();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            return;
        }

        appSyncLock.lock();
        int ret = OCObt.deviceHardReset(ods[userInput], resetDeviceHandler);
        if (ret >= 0) {
            System.out.println("\nSuccessfully issued request to perform hard RESET");
        } else {
            System.out.println("\nERROR issuing request to perform hard RESET");
        }
        appSyncLock.unlock();
    }

    public static void main(String[] args)
    {
        quit = false;
        mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String osName = System.getProperty("os.name");
        boolean isLinux = (osName != null) && osName.toLowerCase().contains("linux");
        System.out.println("OS Name = " + osName + ", isLinux = " + isLinux);

        String creds_path =  "./onboarding_tool_creds/";
        java.io.File directory = new java.io.File(creds_path);
        if (! directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        OCStorage.storageConfig(directory.getPath());

        ObtInitHandler obtHandler = new ObtInitHandler();
        int init_ret = OCMain.mainInit(obtHandler);
        if (init_ret < 0) {
            System.exit(init_ret);
        }

        ocfEventThread.start();

        Scanner scanner = new Scanner(System.in);

        while (!quit) {
            displayMenu();
            int userInput = 0;
            try {
                userInput = scanner.nextInt();
            } catch(InputMismatchException e) {
                System.out.println("Invalid Input.");
                userInput = 0;
            }
            switch(userInput) {
            case 0:
                continue;
            case 1:
            {
                discoverUnownedDevices();
                obtHandler.signalEventLoop();
                break;
            }
            case 2:
                discoverOwnedDevices();
                break;
            case 3:
                takeOwnershipOfDevice();
                break;
            case 4:
                provisionCredentials();
                break;
            case 5:
                provisionAce2();
                break;
            case 6:
                resetDevice();
                break;
            case 9: {
                OCMain.mainShutdown();
                quit = true;
                break;
            }
            default:
                break;
            }
        }
        scanner.close();
        System.exit(0);
    }

}
