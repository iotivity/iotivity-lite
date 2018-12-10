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
    
    public static Set<OCUuidType> unownedDevices = new LinkedHashSet<OCUuidType>();
    public static Set<OCUuidType> ownedDevices = new LinkedHashSet<OCUuidType>();
    private static UnownedDeviceHandler unownedDeviceHandler = new UnownedDeviceHandler();
    private static OwnedDeviceHandler ownedDeviceHandler = new OwnedDeviceHandler();

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
        if (0 < OCObt.discoverOwnedDevices(ownedDeviceHandler)) {
            System.err.println("ERROR discovering owned Devices.");
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
        
        //TODO may need a new thread created here.
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
            case 9: {
                OCMain.mainShutdown();
                quit = true;
            }
            default:
                break;
            }
        }

        System.exit(0);
    }

}
