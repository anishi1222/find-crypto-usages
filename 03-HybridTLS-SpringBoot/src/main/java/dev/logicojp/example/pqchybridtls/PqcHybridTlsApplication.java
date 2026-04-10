package dev.logicojp.example.pqchybridtls;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PqcHybridTlsApplication {

    public static void main(String[] args) {
        applySystemPropertyOverride("APP_TLS_NAMED_GROUPS", "jdk.tls.namedGroups");
        SpringApplication.run(PqcHybridTlsApplication.class, args);
    }

    private static void applySystemPropertyOverride(String environmentVariable, String systemProperty) {
        String value = System.getenv(environmentVariable);
        if (value != null && !value.isBlank()) {
            System.setProperty(systemProperty, value.trim());
        }
    }
}
