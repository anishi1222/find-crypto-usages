import javax.net.ssl.SSLContext;

public class PrintDefaultNamedGroups {

    void main() throws Exception {
        System.out.println("java.runtime.version = " + Runtime.version());
        for (String namedGroup : SSLContext.getDefault().getDefaultSSLParameters().getNamedGroups()) {
            System.out.println(namedGroup);
        }
    }
}
