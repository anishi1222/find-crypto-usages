package dev.logicojp.example.pqchybridtls.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import dev.logicojp.example.pqchybridtls.PqcHybridTlsApplication;

@SpringBootTest(classes = PqcHybridTlsApplication.class)
@AutoConfigureMockMvc
class ApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void helloEndpointReturnsBasicMetadata() throws Exception {
        mockMvc.perform(get("/api/hello").param("name", "Java 27"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello, Java 27!"))
                .andExpect(jsonPath("$.javaVersion").isString())
                .andExpect(jsonPath("$.hybridTlsReady").value(true));
    }

    @Test
    void tlsEndpointReflectsSecureRequestAttributes() throws Exception {
        mockMvc.perform(get("/api/tls")
                        .with(request -> {
                            request.setSecure(true);
                            request.setScheme("https");
                            return request;
                        })
                        .requestAttr("jakarta.servlet.request.cipher_suite", "TLS_AES_256_GCM_SHA384")
                        .requestAttr("jakarta.servlet.request.key_size", 256)
                        .requestAttr("jakarta.servlet.request.ssl_session_id", "session-123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secure").value(true))
                .andExpect(jsonPath("$.scheme").value("https"))
                .andExpect(jsonPath("$.cipherSuite").value("TLS_AES_256_GCM_SHA384"))
                .andExpect(jsonPath("$.keySize").value(256))
                .andExpect(jsonPath("$.sessionId").value("session-123"))
                .andExpect(jsonPath("$.configuredNamedGroups").isString());
    }
}
