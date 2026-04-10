package dev.logicojp.example.pqchybridtls.tools;

import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

public final class PrintDefaultNamedGroups {

    private PrintDefaultNamedGroups() {
    }

    public static void main(String[] args) throws Exception {
        SSLParameters parameters = SSLContext.getDefault().getDefaultSSLParameters();
        String[] namedGroups = parameters.getNamedGroups();
        String override = System.getProperty("jdk.tls.namedGroups");

        System.out.println("java.runtime.version = " + Runtime.version());
        System.out.println("jdk.tls.namedGroups override = "
                + (override == null || override.isBlank() ? "<not set>" : override));

        if (namedGroups == null || namedGroups.length == 0) {
            System.out.println("effective named groups = <provider did not return any values>");
            return;
        }
        // Named groups are retrieved from the default SSLParameters, which reflect the effective configuration after applying any overrides. The first named group in the list is the most preferred one for TLS 1.3 client connections.
        System.out.println("effective named groups = " + Arrays.toString(namedGroups));
        System.out.println("first = " + namedGroups[0]);
    }
}