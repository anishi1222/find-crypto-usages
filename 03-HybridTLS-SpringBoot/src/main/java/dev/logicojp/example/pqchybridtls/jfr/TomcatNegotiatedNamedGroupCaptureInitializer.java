package dev.logicojp.example.pqchybridtls.jfr;

import org.apache.catalina.Service;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public class TomcatNegotiatedNamedGroupCaptureInitializer
        implements ApplicationListener<WebServerInitializedEvent> {

    @Override
    public void onApplicationEvent(WebServerInitializedEvent event) {
        if (!(event.getWebServer() instanceof TomcatWebServer tomcatWebServer)) {
            return;
        }

        Service service = tomcatWebServer.getTomcat().getService();
        for (Connector connector : service.findConnectors()) {
            wrapSslContexts(connector);
        }
    }

    private void wrapSslContexts(Connector connector) {
        for (SSLHostConfig sslHostConfig : connector.findSslHostConfigs()) {
            for (SSLHostConfigCertificate certificate : sslHostConfig.getCertificates()) {
                SSLContext sslContext = certificate.getSslContext();
                if (sslContext == null || sslContext instanceof CapturingTomcatSslContext) {
                    continue;
                }
                certificate.setSslContext(new CapturingTomcatSslContext(sslContext));
            }
        }
    }
}
