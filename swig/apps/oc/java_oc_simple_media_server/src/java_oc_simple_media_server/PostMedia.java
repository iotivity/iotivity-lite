package java_oc_simple_media_server;

import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.layout.StackPane;
import javafx.scene.media.Media;
import javafx.scene.media.MediaPlayer;
import javafx.scene.media.MediaView;
import javafx.stage.Stage;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostMedia implements OCRequestHandler {

    private MediaResource mediaResource;
    private Stage primaryStage;

    public PostMedia(MediaResource mediaResource, Stage primaryStage) {
        this.mediaResource = mediaResource;
        this.primaryStage = primaryStage;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PostMedia RequestHandler");
        if (request.getRequestPayload() != null) {
            OcRepresentation rep = new OcRepresentation(request.getRequestPayload());

            while (rep != null) {
                // TODO ?
                rep = rep.getNext();
            }
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        // no data
        root.done();

        System.out.println("Setting media to " + mediaResource.getUrl());
        if (primaryStage != null) {
            Platform.runLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        Media media = new Media(mediaResource.getUrl());
                        MediaPlayer mediaPlayer = new MediaPlayer(media);
                        MediaView mediaView = new MediaView(mediaPlayer);

                        StackPane pane = new StackPane();
                        pane.getChildren().add(mediaView);

                        Scene scene = new Scene(pane, 600, 400);
                        primaryStage.setScene(scene);
                        primaryStage.setUserData(mediaPlayer);
                        primaryStage.setTitle("Simple Media Server - " + mediaResource.getName());

                    } catch (Exception e) {
                        System.err.println("Error " + e);
                    }
                }
            });
        }

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}
