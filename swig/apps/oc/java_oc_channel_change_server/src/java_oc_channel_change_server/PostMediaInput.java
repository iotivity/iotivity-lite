package java_oc_channel_change_server;

import java.util.ArrayList;
import java.util.List;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostMediaInput implements OCRequestHandler {

    private MediaInput mediaInput;

    public PostMediaInput(MediaInput mediaInput) {
        this.mediaInput = mediaInput;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostMediaInput RequestHandler");
        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());

        if ("sources".equalsIgnoreCase(rep.getKey())) {
            try {
                OcRepresentation sourcesList = rep.getObjectArray("sources");

                List<MediaSource> mediaSources = new ArrayList<>();

                while (sourcesList != null) {
                    OcRepresentation mediaObject = sourcesList.getObject();

                    MediaSource mediaSource = new MediaSource();
                    while (mediaObject != null) {
                        try {
                            if ("sourceName".equalsIgnoreCase(mediaObject.getKey())) {
                                mediaSource.setSourceName(mediaObject.getString("sourceName"));
                            }
                        } catch (OcCborException e) {
                            // ignore -- no source name
                        }

                        try {
                            if ("sourceNumber".equalsIgnoreCase(mediaObject.getKey())) {
                                mediaSource.setSourceNumber(mediaObject.getString("sourceNumber"));
                            }
                        } catch (OcCborException e) {
                            // ignore -- no source number
                        }

                        try {
                            if ("sourceType".equalsIgnoreCase(mediaObject.getKey())) {
                                String sourceType = mediaObject.getString("sourceType");
                                if (sourceType != null) {
                                    if (sourceType.equalsIgnoreCase(MediaSource.SourceType.audioOnly.toString())) {
                                        mediaSource.setSourceType(MediaSource.SourceType.audioOnly);
                                    } else if (sourceType
                                            .equalsIgnoreCase(MediaSource.SourceType.videoOnly.toString())) {
                                        mediaSource.setSourceType(MediaSource.SourceType.videoOnly);
                                    } else if (sourceType
                                            .equalsIgnoreCase(MediaSource.SourceType.audioPlusVideo.toString())) {
                                        mediaSource.setSourceType(MediaSource.SourceType.audioPlusVideo);
                                    } else {
                                        // ignore -- unknown source type
                                    }
                                }
                            }
                        } catch (OcCborException e) {
                            // ignore -- no source type
                        }

                        try {
                            if ("status".equalsIgnoreCase(mediaObject.getKey())) {
                                mediaSource.setSourceStatus(mediaObject.getBoolean("status"));
                            }
                        } catch (OcCborException e) {
                            // ignore -- no status
                        }

                        mediaObject = mediaObject.getNext();
                    }

                    mediaSources.add(mediaSource);

                    sourcesList = sourcesList.getNext();
                }

                mediaInput.setMediaSources(mediaSources.toArray(new MediaSource[0]));

            } catch (OcCborException e) {
                // ignore -- no sources list
            }
        }
    }
}
