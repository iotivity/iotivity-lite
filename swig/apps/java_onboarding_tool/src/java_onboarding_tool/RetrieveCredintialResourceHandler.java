package java_onboarding_tool;

import org.iotivity.OCCreds;
import org.iotivity.OCObt;
import org.iotivity.OCObtCredsHandler;

public class RetrieveCredintialResourceHandler implements OCObtCredsHandler {

    @Override
    public void handler(OCCreds creds) {
        if (creds != null) {
            ObtMain.displayCredentialResource(creds);
            /* Freeing the credential structure */
            OCObt.freeCreds(creds);
        } else {
            System.out.println("\nERROR RETRIEving /oic/sec/cred");
        }
    }

}
