package java_oc_simple_media_server;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ServerApp extends Application {

    static private OcPlatform ocPlatform = OcPlatform.getInstance();

    public static void main(String args[]) {
        launch(args);
    }

    public void start(Stage primaryStage) {

        String storage_path = "./simplemediaserver_store/";
        java.io.File directory = new java.io.File(storage_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            @Override
            public void handle(WindowEvent event) {
                System.out.println("Calling platform shutdown.");
                ocPlatform.systemShutdown();
                Platform.exit();
            }
        });

        InitHandler initHandler = new InitHandler(ocPlatform, primaryStage);
        ocPlatform.systemInit(initHandler);

        StackPane pane = new StackPane();
        Scene scene = new Scene(pane, 600, 400);
        primaryStage.setScene(scene);

        primaryStage.setTitle("Simple Media Server");
        primaryStage.show();
    }
}
