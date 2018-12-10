package java_onboarding_tool;

import java.util.InputMismatchException;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.iotivity.OCClock;
import org.iotivity.OCMain;
import org.iotivity.OCObt;
import org.iotivity.OCStorage;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidType;

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

    public static Set<OCUuidType> unownedDevices = new LinkedHashSet<OCUuidType>();
    public static Set<OCUuidType> ownedDevices = new LinkedHashSet<OCUuidType>();

    private static UnownedDeviceHandler unownedDeviceHandler = new UnownedDeviceHandler();
    private static OwnedDeviceHandler ownedDeviceHandler = new OwnedDeviceHandler();
    private static JustWorksHandler justWorksHandler = new JustWorksHandler();
    private static ProvisionCredentialsHandler provisionCredentialsHandler = new ProvisionCredentialsHandler();
    private static ResetDeviceHandler resetDeviceHandler = new ResetDeviceHandler();

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
        System.out.println("\nSelect option: ");
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
        OCUuidType[] uds = (OCUuidType[]) unownedDevices.toArray();
        for(OCUuidType ud : uds) {
            System.out.println("[" + i + "]: " + OCUuid.uuidToString(ud));
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
        OCUuidType[] ods = (OCUuidType[]) ownedDevices.toArray();
        for(OCUuidType od : ods) {
            System.out.println("[" + i + "]: " + OCUuid.uuidToString(od));
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

    public static void resetDevice() {
        if(ownedDevices.isEmpty()) {
            System.out.println("\n\nPlease Re-Discover Owned devices");
            return;
        }

        int i = 0;

        System.out.println("\nMy Devices:");
        OCUuidType[] ods = (OCUuidType[]) ownedDevices.toArray();
        for(OCUuidType od : ods) {
            System.out.println("[" + i + "]: " + OCUuid.uuidToString(od));
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
