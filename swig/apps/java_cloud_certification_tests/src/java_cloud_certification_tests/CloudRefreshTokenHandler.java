package java_cloud_certification_tests;

import org.iotivity.OCCloud;
import org.iotivity.OCCloudContext;
import org.iotivity.OCCloudHandler;
import org.iotivity.OCCloudStatusMask;

public class CloudRefreshTokenHandler implements OCCloudHandler {

    @Override
    public void handler(OCCloudContext ctx, int status) {
        System.out.println("\nCloud Refresh Token status flags:");
        if ((status & OCCloudStatusMask.OC_CLOUD_REGISTERED) == OCCloudStatusMask.OC_CLOUD_REGISTERED) {
            System.out.println("\t\t-Registered");
        }
        if ((status & OCCloudStatusMask.OC_CLOUD_TOKEN_EXPIRY) == OCCloudStatusMask.OC_CLOUD_TOKEN_EXPIRY) {
            System.out.println("\t\t-Token Expiry:");
            if (ctx != null) {
                System.out.println(OCCloud.getTokenExpiry(ctx));
            }
        }
        if ((status & OCCloudStatusMask.OC_CLOUD_FAILURE) == OCCloudStatusMask.OC_CLOUD_FAILURE) {
            System.out.println("\t\t-Failure");
        }
        if ((status & OCCloudStatusMask.OC_CLOUD_LOGGED_IN) == OCCloudStatusMask.OC_CLOUD_LOGGED_IN) {
            System.out.println("\t\t-Logged In");
        }
        if ((status & OCCloudStatusMask.OC_CLOUD_LOGGED_OUT) == OCCloudStatusMask.OC_CLOUD_LOGGED_OUT) {
            System.out.println("\t\t-Logged Out");
        }
        if ((status & OCCloudStatusMask.OC_CLOUD_DEREGISTERED) == OCCloudStatusMask.OC_CLOUD_DEREGISTERED) {
            System.out.println("\t\t-DeRegistered");
        }
        if ((status & OCCloudStatusMask.OC_CLOUD_REFRESHED_TOKEN) == OCCloudStatusMask.OC_CLOUD_REFRESHED_TOKEN) {
            System.out.println("\t\t-Refreshed Token");
        }
    }
}
