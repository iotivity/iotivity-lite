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
          exit_status = 1;
        }

        System.out.println("Running OCEndpointTest tests.");
        result = junit.run(OCEndpointTest.class);
        if (result.getFailureCount() > 0) {
          exit_status = 1;
        }

        /* Currently OCMainTest contains no runnable test code.
        System.out.println("Running OCMainTest tests.");
        result = junit.run(OCMainTest.class);
        if (result.getFailureCount() > 0) {
          exit_status = 1;
        }
        */

        System.out.println("Running OCOwnershipTransferMethodsTest tests.");
        result = junit.run(OCOwnershipTransferMethodsTest.class);
        if (result.getFailureCount() > 0) {
          exit_status = 1;
        }

        System.out.println("Running OCRandom tests.");
        result = junit.run(OCRandomTest.class);
        if (result.getFailureCount() > 0) {
          exit_status = 1;
        }

        System.out.println("Running OCRepresentationTest tests.");
        result = junit.run(OCRepresentationTest.class);
        if (result.getFailureCount() > 0) {
          exit_status = 1;
        }

        System.out.println("Running OCUuidTest tests.");
        result = junit.run(OCUuidTest.class);
        if (result.getFailureCount() > 0) {
          exit_status = 1;
        }

        System.exit(exit_status);
      }
}
