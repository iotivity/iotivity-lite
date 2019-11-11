package org.iotivity;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.internal.TextListener;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;

public class TestRunner {
    public static void main(String args[]) {
        JUnitCore junit = new JUnitCore();
        junit.addListener(new TextListener(System.out));
        Result result;
        int exit_status = 0;
        System.out.println("Running OCCredTest tests.");
        result = junit.run(OCCredTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("OCCredTest Tests FAILED.");
          exit_status = 1;
        } else {
          System.out.println("OCCredTest tests finished SUCCESSFULLY.");
        }

        System.out.println("Running OCEndpointTest tests.");
        result = junit.run(OCEndpointTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("OCEndpointTest Tests FAILED.");
          exit_status = 1;
        } else {
          System.out.println("OCEndpointTest tests finished SUCCESSFULLY.");
        }


        /* Currently OCMainTest contains not runnable test code.
        System.out.println("Running OCMainTest tests.");
        result = junit.run(OCMainTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("OCMainTest Tests FAILED.");
          exit_status = 1;
        } else {
          System.out.println("OCMainTest tests finished SUCCESSFULLY.");
        }
        */

        System.out.println("Running OCOwnershipTransferMethodsTest tests.");
        result = junit.run(OCOwnershipTransferMethodsTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("OCOwnershipTransferMethodsTest Tests FAILED.");
          exit_status = 1;
        } else {
          System.out.println("OCOwnershipTransferMethodsTest tests finished SUCCESSFULLY.");
        }

        System.out.println("Running OCRepresentationTest tests.");
        result = junit.run(OCRepresentationTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("OCRepresentationTest Tests FAILED.");
          exit_status = 1;
        } else {
          System.out.println("OCRepresentationTest tests finished SUCCESSFULLY.");
        }

        System.out.println("Running OCUuidTest tests.");
        result = junit.run(OCUuidTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("OCUuidTest Tests FAILED.");
          exit_status = 1;
        } else {
          System.out.println("OCUuidTest tests finished SUCCESSFULLY.");
        }

        System.exit(exit_status);
      }
}
