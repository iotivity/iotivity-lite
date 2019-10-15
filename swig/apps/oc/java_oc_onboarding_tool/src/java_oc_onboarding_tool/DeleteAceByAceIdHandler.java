package java_oc_onboarding_tool;

import org.iotivity.OCObtStatusHandler;

public class DeleteAceByAceIdHandler implements OCObtStatusHandler {

    @Override
    public void handler(int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully DELETED ace");
          } else {
            System.out.println("\nERROR DELETING ace");
          }
    }

}
