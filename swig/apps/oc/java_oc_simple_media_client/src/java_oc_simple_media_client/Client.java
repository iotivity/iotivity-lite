package java_oc_simple_media_client;

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

    static private Set<OcfServerResource> mediaResources = Collections.synchronizedSet(new LinkedHashSet<>());
    static private Set<OcfServerResource> mediaControlResources = Collections.synchronizedSet(new LinkedHashSet<>());

    static private MediaResource currentMediaResource;
    static private MediaControlResource currentMediaControlResource;

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
        menu.append("Simple Media Client\n");
        menu.append("################################################\n");
        menu.append("[0] Display this menu\n");
        menu.append("------------------------------------------------\n");
        menu.append("[1] Discover media resources\n");
        menu.append("[2] Select media resource\n");
        menu.append("------------------------------------------------\n");
        menu.append("[3] Discover media control resources\n");
        menu.append("[4] Select media control resource\n");
        menu.append("------------------------------------------------\n");
        menu.append("[5] Select new action\n");
        menu.append("[6] Set URI Expression\n");
        menu.append("------------------------------------------------\n");
        menu.append("[7] Start observe\n");
        menu.append("[8] Stop observe\n");
        menu.append("------------------------------------------------\n");
        menu.append("[9] Exit\n");
        menu.append("################################################\n");
        menu.append("\nSelect option: ");
        System.out.print(menu);
    }

    static private void discoverMediaResources() {
        System.out.println("Discovering media resources");
        mediaResources.clear();
        DiscoveryHandler discoveryHandler = new DiscoveryHandler(mediaResources);
        OcUtils.doIPDiscovery("oic.r.media", discoveryHandler);
    }

    static private void selectMediaResource() {
        if (mediaResources.isEmpty()) {
            System.out.println("\nNo media resources found\nPlease re-discover media resources");
            return;
        }

        int i = 0;

        StringBuilder mediaResourcesMenu = new StringBuilder();
        mediaResourcesMenu.append("\nMedia Resources:\n");
        OcfServerResource[] resources = mediaResources.toArray(new OcfServerResource[0]);
        for (OcfServerResource resource : resources) {
            mediaResourcesMenu.append("[" + i + "]: " + resource.getServerUri() + "\n");
            i++;
        }
        mediaResourcesMenu.append("\n\nSelect resource: ");
        System.out.print(mediaResourcesMenu);

        int userInput = getIntUserInput();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            scanner.nextLine();
            return;
        }

        if (currentMediaControlResource != null) {
            sendUriExpression("mediaaction=stop");
        }
        currentMediaResource = (MediaResource) resources[userInput];
        GetMediaResourceResponseHandler responseHandler = new GetMediaResourceResponseHandler(currentMediaResource);
        OcUtils.doGet(currentMediaResource.getServerUri(), currentMediaResource.getServerEndpoint(), null,
                responseHandler, OCQos.LOW_QOS);
    }

    static private void discoverMediaControlResources() {
        System.out.println("Discovering media control resources");
        mediaControlResources.clear();
        DiscoveryHandler discoveryHandler = new DiscoveryHandler(mediaControlResources);
        OcUtils.doIPDiscovery("oic.r.media.control", discoveryHandler);
    }

    static private void selectMediaControlResource() {
        if (mediaControlResources.isEmpty()) {
            System.out.println("\nNo media control resources found\nPlease re-discover media control resources");
            return;
        }

        int i = 0;

        StringBuilder mediaControlResourcesMenu = new StringBuilder();
        mediaControlResourcesMenu.append("\nMedia Control Resources:\n");
        OcfServerResource[] resources = mediaControlResources.toArray(new OcfServerResource[0]);
        for (OcfServerResource resource : resources) {
            mediaControlResourcesMenu.append("[" + i + "]: " + resource.getServerUri() + "\n");
            i++;
        }
        mediaControlResourcesMenu.append("\n\nSelect resource: ");
        System.out.print(mediaControlResourcesMenu);

        int userInput = getIntUserInput();
        if (userInput < 0 || userInput >= i) {
            System.out.println("ERROR: Invalid selection");
            scanner.nextLine();
            return;
        }

        currentMediaControlResource = (MediaControlResource) resources[userInput];
        GetMediaControlResourceResponseHandler responseHandler = new GetMediaControlResourceResponseHandler(
                currentMediaControlResource);
        OcUtils.doGet(currentMediaControlResource.getServerUri(), currentMediaControlResource.getServerEndpoint(), null,
                responseHandler, OCQos.LOW_QOS);
    }

    static private void selectAction() {
        if (currentMediaControlResource == null) {
            System.out.println("\nNo media control resource selected\nPlease select media control resource");
            return;
        }

        int i = 0;

        StringBuilder selectActionMenu = new StringBuilder();
        selectActionMenu.append("\nAvaliable actions:\n");
        String[] actions = currentMediaControlResource.getAllowedActions();
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

        sendUriExpression("mediaaction=" + actions[userInput]);
    }

    static private void setUriExpression() {
        System.out.println("Set Uri Expression");
        if (currentMediaControlResource == null) {
            System.out.println("\nNo media control resource selected\nPlease select media control resource");
            return;
        }

        String[] params = new String[] { "", "", "", "" };

        System.out.print("Set media action? [0-No, 1-Yes]: ");
        int userInput = getIntUserInput();
        if (userInput == 1) {
            int i = 0;
            StringBuilder selectActionMenu = new StringBuilder();
            selectActionMenu.append("\nAvaliable actions:\n");
            String[] actions = currentMediaControlResource.getAllowedActions();
            for (String action : actions) {
                selectActionMenu.append("[" + i + "]: " + action + "\n");
                i++;
            }
            selectActionMenu.append("\n\nSelect action: ");
            System.out.print(selectActionMenu);

            userInput = getIntUserInput();
            if (userInput < 0 || userInput >= i) {
                System.out.println("ERROR: Invalid selection");
                scanner.nextLine();
                return;
            }

            params[0] = "mediaaction=" + actions[userInput];
        }

        System.out.print("Set play state? [0-No, 1-Yes]: ");
        userInput = getIntUserInput();
        if (userInput == 1) {
            System.out.print("Enter play state [0-False, 1-True]: ");
            userInput = getIntUserInput();
            params[1] = "playstate=" + ((userInput == 1) ? "true" : "false");
        }

        System.out.print("Set media speed? [0-No, 1-Yes]: ");
        userInput = getIntUserInput();
        if (userInput == 1) {
            StringBuilder inputMsgSuffix = new StringBuilder();
            if (params[0].contains("fastforward")) {
                double[] allowedValues = currentMediaControlResource.getFastforwardAllowedValues();
                if ((allowedValues != null) && (allowedValues.length > 0)) {
                    for (double value : allowedValues) {
                        if (inputMsgSuffix.length() > 0) {
                            inputMsgSuffix.append(", ");
                        }
                        inputMsgSuffix.append(value);
                    }
                }
            }
            if (params[0].contains("rewind")) {
                double[] allowedValues = currentMediaControlResource.getRewindAllowedValues();
                if ((allowedValues != null) && (allowedValues.length > 0)) {
                    for (double value : allowedValues) {
                        if (inputMsgSuffix.length() > 0) {
                            inputMsgSuffix.append(", ");
                        }
                        inputMsgSuffix.append(value);
                    }
                }
            }
            if (inputMsgSuffix.length() == 0) {
                inputMsgSuffix.append("eg 1.0");
            }
            System.out.print("Enter media speed (" + inputMsgSuffix + "): ");
            params[2] = "mediaspeed=" + scanner.nextDouble();
        }

        System.out.print("Set media location? [0-No, 1-Yes]: ");
        userInput = getIntUserInput();
        if (userInput == 1) {
            StringBuilder inputMsgSuffix = new StringBuilder();
            if (params[0].contains("stepforward")) {
                double[] range = currentMediaControlResource.getStepForwardRange();
                if ((range != null) && (range.length > 0)) {
                    for (double value : range) {
                        if (inputMsgSuffix.length() > 0) {
                            inputMsgSuffix.append(" - ");
                        }
                        inputMsgSuffix.append(value);
                    }
                }
            }
            if (params[0].contains("stepbackward")) {
                double[] range = currentMediaControlResource.getStepBackwardRange();
                if ((range != null) && (range.length > 0)) {
                    for (double value : range) {
                        if (inputMsgSuffix.length() > 0) {
                            inputMsgSuffix.append(" - ");
                        }
                        inputMsgSuffix.append(value);
                    }
                }
            }
            if (params[0].contains("seek")) {
                double[] range = currentMediaControlResource.getSeekRange();
                if ((range != null) && (range.length > 0)) {
                    for (double value : range) {
                        if (inputMsgSuffix.length() > 0) {
                            inputMsgSuffix.append(" - ");
                        }
                        inputMsgSuffix.append(value);
                    }
                }
            }
            if (inputMsgSuffix.length() == 0) {
                inputMsgSuffix.append("eg 500.0");
            }
            System.out.print("Enter media location (" + inputMsgSuffix + "): ");
            params[3] = "medialocation=" + scanner.nextDouble();
        }

        StringBuilder uriExpression = new StringBuilder();
        for (int i = 0; i < params.length; ++i) {
            if (!params[i].isEmpty()) {
                if (uriExpression.length() > 0) {
                    uriExpression.append("&");
                }
                uriExpression.append(params[i]);
            }
        }

        sendUriExpression(uriExpression.toString());
    }

    static private void sendUriExpression(String uriExp) {
        PostMediaControlResourceResponseHandler postHandler = new PostMediaControlResourceResponseHandler(
                currentMediaControlResource);
        if (OcUtils.initPost(currentMediaControlResource.getServerUri(),
                currentMediaControlResource.getServerEndpoint(), uriExp, postHandler, OCQos.LOW_QOS)) {

            OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
            root.setTextString("uriexp", uriExp);
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
        if (currentMediaControlResource == null) {
            System.out.println("\nNo media control resource selected\nPlease select media control resource");
            return;
        }

        ObserveMediaControlResourceResponseHandler observerHandler = new ObserveMediaControlResourceResponseHandler(
                currentMediaControlResource);
        OcUtils.doObserve(currentMediaControlResource.getServerUri(), currentMediaControlResource.getServerEndpoint(),
                null, observerHandler, OCQos.LOW_QOS);
        observing = true;
    }

    static private void stopObserve() {
        if (currentMediaControlResource != null) {
            OcUtils.stopObserve(currentMediaControlResource.getServerUri(),
                    currentMediaControlResource.getServerEndpoint());
        }
        observing = false;
    }

    public static void main(String argv[]) {
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String storage_path = "./simplemediaclient_store/";
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
                discoverMediaResources();
                break;
            case 2:
                selectMediaResource();
                break;
            case 3:
                discoverMediaControlResources();
                break;
            case 4:
                selectMediaControlResource();
                break;
            case 5:
                selectAction();
                break;
            case 6:
                setUriExpression();
                break;
            case 7:
                startObserve();
                break;
            case 8:
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
