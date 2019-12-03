package java_cloud_certification_tests;

import java.util.InputMismatchException;
import java.util.Scanner;

import org.iotivity.OCBufferSettings;
import org.iotivity.OCCloud;
import org.iotivity.OCCloudContext;
import org.iotivity.OCMain;
import org.iotivity.OCObt;
import org.iotivity.OCStorage;

public class CloudCertTestsMain {

    /* user input Scanner */
    private static Scanner scanner = new Scanner(System.in);

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

    public static void displayMenu() {
        StringBuilder menu = new StringBuilder();
        menu.append("\n################################################\n");
        menu.append("OCF Cloud-connect Device Certification Test tool\n");
        menu.append("################################################\n");
        menu.append("[0] Display this menu\n");
        menu.append("------------------------------------------------\n");
        menu.append("[1] Cloud Register\n");
        menu.append("[2] Cloud Login\n");
        menu.append("[3] Cloud Logout\n");
        menu.append("[4] Cloud DeRegister\n");
        menu.append("[5] Cloud Refresh Token\n");
        menu.append("[6] Publish Resources\n");
        menu.append("------------------------------------------------\n");
        menu.append("[7] Reset Ready for OTM\n");
        menu.append("------------------------------------------------\n");
        menu.append("[8] Exit\n");
        menu.append("################################################\n");
        menu.append("\nSelect option: ");
        System.out.print(menu);
    }

    private static CloudRegisterHandler cloudRegisterHandler = new CloudRegisterHandler();
    public static void cloudRegister() {
        OCCloudContext ctx = OCCloud.getContext(0);
        if (ctx == null) {
            return;
        }
        int ret = OCCloud.registerCloud(ctx, cloudRegisterHandler);
        if (ret < 0) {
            System.out.println("\nCould not issue Cloud Register request.");
        } else {
            System.out.println("\nIssued Cloud Register request.");
        }
    }

    private static CloudLoginHandler cloudLoginHandler = new CloudLoginHandler();
    public static void cloudLogin() {
        OCCloudContext ctx = OCCloud.getContext(0);
        if (ctx == null) {
            return;
        }
        
        int ret = OCCloud.login(ctx, cloudLoginHandler);
        if (ret < 0) {
            System.out.println("\nCould not issue Cloud Login request");
        } else {
            System.out.println("\nIssued Cloud Login Request.");
        }
    }

    private static CloudLogoutHandler cloudLogoutHandler = new CloudLogoutHandler();
    public static void cloudLogout() {
        OCCloudContext ctx = OCCloud.getContext(0);
        if (ctx == null) {
            return;
        }
        
        int ret = OCCloud.logout(ctx, cloudLogoutHandler);
        if (ret < 0) {
            System.out.println("\nCould not issue Cloud Logout request");
        } else {
            System.out.println("\nIssued Cloud Logout Request.");
        }
    }
    
    private static CloudDeregisterHandler cloudDeregisterHandler = new CloudDeregisterHandler();
    public static void cloudDeregister() {
        OCCloudContext ctx = OCCloud.getContext(0);
        if (ctx == null) {
            return;
        }
        int ret = OCCloud.deregisterCloud(ctx, cloudDeregisterHandler);
        if (ret < 0) {
            System.out.println("\nCould not issue Cloud DeRegister request");
        } else {
            System.out.println("\nIssued Cloud DeRegister Request.");
        }
    }

    private static CloudRefreshTokenHandler cloudRefreshTokenHandler = new CloudRefreshTokenHandler();
    public static void cloudRefreshToken() {
        OCCloudContext ctx = OCCloud.getContext(0);
        if (ctx == null) {
            return;
        }
        int ret = OCCloud.refreshToken(ctx, cloudRefreshTokenHandler);
        if (ret < 0) {
            System.out.println("\nCould not issue Refresh Token request");
        } else {
            System.out.println("\nIssued Refresh Token Request.");
        }
    }
    
    public static void cloudPublishResources() {
        int ret = OCCloud.publishResources(0);
        if (ret < 0) {
            System.out.println("\nCould not publish resources");
        } else {
            System.out.println("\nResources successfully published.");
        }
    }
    
    public static void resetOTM() {
        OCMain.reset();
    }

    public static void main(String[] args) {
        quit = false;
        mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String creds_path = "./cloud_tests_creds/";
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        OCMain.setConResAnnounced(false);
        OCBufferSettings.setMaxAppDataSize(6000);
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
                cloudRegister();
                break;
            case 2:
                cloudLogin();
                break;
            case 3:
                cloudLogout();
                break;
            case 4:
                cloudDeregister();
                break;
            case 5:
                cloudRefreshToken();
                break;
            case 6:
                cloudPublishResources();
                break;
            case 7:
                resetOTM();
                break;
            case 8:
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
