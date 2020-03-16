package java_oc_channel_change_client;

import java.util.Collections;
import java.util.InputMismatchException;
import java.util.LinkedHashSet;
import java.util.Scanner;
import java.util.Set;

import org.iotivity.*;
import org.iotivity.oc.*;

public class Client {

    static private Scanner scanner = new Scanner(System.in);
    static private OcPlatform platform = OcPlatform.getInstance();
    static private Thread mainThread = Thread.currentThread();
    static private boolean quit;
    static private boolean observing;

    static private Set<OcfServerResource> channelChangeResources = Collections.synchronizedSet(new LinkedHashSet<>());
    static private ChannelChangeResource channelChangeResource;

    static private Thread shutdownHook = new Thread() {
        public void run() {
            quit = true;
            System.out.println("Calling platform shutdown.");
            platform.systemShutdown();
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

    static private void displayMenu() {
        StringBuilder menu = new StringBuilder();
        menu.append("\n################################################\n");
        menu.append("Channel Change Client\n");
        menu.append("################################################\n");
        menu.append("[0] Display this menu\n");
        menu.append("------------------------------------------------\n");
        menu.append("[1] Discover channel change resources\n");
        menu.append("[2] Select channel change resource\n");
        menu.append("------------------------------------------------\n");
        menu.append("[3] Select channel action\n");
        menu.append("[4] Set channel id \n");
        menu.append("------------------------------------------------\n");
        menu.append("[5] Start observe\n");
        menu.append("[6] Stop observe\n");
        menu.append("------------------------------------------------\n");
        menu.append("[9] Exit\n");
        menu.append("################################################\n");
        menu.append("\nSelect option: ");
        System.out.print(menu);
    }

    static private void discoverMediaResources() {
    }

    static private void selectMediaResource() {
    }

    static private void discoverChannelChangeResources() {
        System.out.println("Discovering channel change resources");
        channelChangeResources.clear();
        DiscoveryHandler discoveryHandler = new DiscoveryHandler(channelChangeResources);
        OcUtils.doIPDiscovery("oic.r.channelchange", discoveryHandler);
    }

    static private void selectChannelChangeResource() {
        if (channelChangeResources.isEmpty()) {
            System.out.println("\nNo channel change resources found\nPlease re-discover channel change resources");
            return;
        }

        int i = 0;

        StringBuilder channelChangeResourcesMenu = new StringBuilder();
        channelChangeResourcesMenu.append("\nChannel Change Resources:\n");
        OcfServerResource[] resources = channelChangeResources.toArray(new OcfServerResource[0]);
        for (OcfServerResource resource : resources) {
            channelChangeResourcesMenu.append("[" + i + "]: " + resource.getServerUri() + "\n");
            i++;
        }
        channelChangeResourcesMenu.append("\n\nSelect resource: ");
        System.out.print(channelChangeResourcesMenu);

        int userInput = getIntUserInput();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            scanner.nextLine();
            return;
        }

        channelChangeResource = (ChannelChangeResource) resources[userInput];
        GetChannelChangeResourceResponseHandler responseHandler = new GetChannelChangeResourceResponseHandler(
                channelChangeResource);
        OcUtils.doGet(channelChangeResource.getServerUri(), channelChangeResource.getServerEndpoint(), null,
                responseHandler, OCQos.LOW_QOS);
    }

    static private void selectAction() {
        if (channelChangeResource == null) {
            System.out.println("\nNo channel change resource selected\nPlease select channel change resource");
            return;
        }

        int i = 0;

        StringBuilder selectActionMenu = new StringBuilder();
        selectActionMenu.append("\nAvaliable actions:\n");
        String[] actions = channelChangeResource.getActions();
        for (String action : actions) {
            selectActionMenu.append("[" + i + "]: " + action + "\n");
            i++;
        }
        selectActionMenu.append("\n\nSelect action: ");
        System.out.print(selectActionMenu);

        int userInput = getIntUserInput();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            scanner.nextLine();
            return;
        }

        sendMessage("action", actions[userInput], 0);
    }

    static private void setChannelId() {
        System.out.println("\nSet Channel Id");
        if (channelChangeResource == null) {
            System.out.println("\nNo channel change resource selected\nPlease select channel change resource");
            return;
        }

        System.out.print("Enter Channel Id: ");
        int channelId = 0;
        try {
            channelId = getIntUserInput();
        } catch (InputMismatchException e) {
            System.out.println("ERROR: Invalid selection");
            scanner.nextLine();
            return;
        }

        sendMessage("channelid", null, channelId);
    }

    static private void sendMessage(String key, String value, int channelId) {
        String query = null;
        if (value != null) {
            query = key + "=" + value;
        }
        if (channelId > 0) {
            query = key + "=" + channelId;
        }

        PostChannelChangeResourceResponseHandler postHandler = new PostChannelChangeResourceResponseHandler(
                channelChangeResource);
        if (OcUtils.initPost(channelChangeResource.getServerUri(), channelChangeResource.getServerEndpoint(), query,
                postHandler, OCQos.LOW_QOS)) {

            OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
            if (value != null) {
                root.setTextString(key, value);
            }
            if (channelId > 0) {
                root.setLong(key, channelId);
            }
            root.done();

            if (OcUtils.doPost()) {
                // successfully sent POST
            } else {
                System.out.println("Could not send POST request");
            }
        } else {
            System.out.println("Could not init POST request");
        }
    }

    static private void startObserve() {
        if (channelChangeResource == null) {
            System.out.println("\nNo channel change resource selected\nPlease select channel change resource");
            return;
        }

        ObserveChannelChangeResourceResponseHandler observerHandler = new ObserveChannelChangeResourceResponseHandler(
                channelChangeResource);
        OcUtils.doObserve(channelChangeResource.getServerUri(), channelChangeResource.getServerEndpoint(), null,
                observerHandler, OCQos.LOW_QOS);
        observing = true;
    }

    static private void stopObserve() {
        if (channelChangeResource != null) {
            OcUtils.stopObserve(channelChangeResource.getServerUri(), channelChangeResource.getServerEndpoint());
        }
        observing = false;
    }

    public static void main(String argv[]) {
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String storage_path = "./channelchangeclient_store/";
        java.io.File directory = new java.io.File(storage_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        InitHandler initHandler = new InitHandler(platform);
        platform.systemInit(initHandler);

        while (!quit) {
            if (!observing) {
                displayMenu();
            }
            int userInput = 0;
            try {
                userInput = getIntUserInput();
            } catch (InputMismatchException e) {
                System.out.println("Invalid Input.");
                scanner.nextLine();
                userInput = 0;
            }
            switch (userInput) {
            case 0:
                continue;
            case 1:
                discoverChannelChangeResources();
                break;
            case 2:
                selectChannelChangeResource();
                break;
            case 3:
                selectAction();
                break;
            case 4:
                setChannelId();
                break;
            case 5:
                startObserve();
                break;
            case 6:
                stopObserve();
                try {
                    // wait for final observe message
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                }
                break;
            case 9:
                quit = true;
                break;
            default:
                break;
            }
        }

        platform.systemShutdown();
        scanner.close();
        System.exit(0);
    }
}
