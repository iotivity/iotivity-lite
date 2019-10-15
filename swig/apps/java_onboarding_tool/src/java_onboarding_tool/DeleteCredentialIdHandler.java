package java_onboarding_tool;

import org.iotivity.OCObtStatusHandler;

public class DeleteCredentialIdHandler implements OCObtStatusHandler {

    @Override
    public void handler(int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully DELETEd cred");
          } else {
              System.out.println("\nERROR DELETing cred");
          }
    }

}
