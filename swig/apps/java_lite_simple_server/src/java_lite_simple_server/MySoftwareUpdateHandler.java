package java_lite_simple_server;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import org.iotivity.*;

public class MySoftwareUpdateHandler implements OCSoftwareUpdateHandler {

    @Override
    public int validatePURL(String url) {
        System.out.println("swupdate validating url " + url);
        try {
            URL urlObject = new URL(url);
            URLConnection conn = urlObject.openConnection();
            conn.connect();
        } catch (MalformedURLException e) {
            System.err.println("Software Update URL is not in a valid form: " + url);
            return -1;
        } catch (IOException e) {
            System.err.println("Connection to Software Update URL could not be established: " + url);
            return -1;
        }
        return 0;
    }

    @Override
    public int checkNewVersion(long device, String url, String version) {
        System.out.println("swupdate checkNewVersion: device = " + device + ", url = " + url);
        if (url == null) {
            OCSoftwareUpdate.notifyDone(device, OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_INVALID_URL);
            return -1;
        }
        if (version != null) {
            System.out.println("swupdate new version = " + version);
        }
        OCSoftwareUpdate.notifyNewVersionAvailable(device, "10.0", OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
        return 0;
    }

    @Override
    public int downloadUpdate(long device, String url) {
        System.out.println("swupdate downloadUpdate: device = " + device + ", url = " + url);
        OCSoftwareUpdate.notifyDownload(device, "10.0", OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
        return 0;
    }

    @Override
    public int performUpgrade(long device, String url) {
        System.out.println("swupdate performUpgrade: device = " + device + ", url = " + url);
        OCSoftwareUpdate.notifyUpgrading(device, "10.0", System.currentTimeMillis(),
                OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
        OCSoftwareUpdate.notifyDone(device, OCSoftwareUpdateResult.OC_SWUPDATE_RESULT_SUCCESS);
        return 0;
    }
}
