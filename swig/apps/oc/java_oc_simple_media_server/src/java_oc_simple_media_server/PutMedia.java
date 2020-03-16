package java_oc_simple_media_server;

import javafx.stage.Stage;

import org.iotivity.*;

public class PutMedia implements OCRequestHandler {

    private MediaResource mediaResource;
    private Stage primaryStage;

    public PutMedia(MediaResource mediaResource, Stage primaryStage) {
        this.mediaResource = mediaResource;
        this.primaryStage = primaryStage;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PutMedia RequestHandler");
        new PostMedia(mediaResource, primaryStage).handler(request, interfaces);
    }
}
