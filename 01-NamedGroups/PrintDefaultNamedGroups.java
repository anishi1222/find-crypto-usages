import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

public final class PrintDefaultNamedGroups {

  void main(String[] args) throws Exception {
    IO.println("java.runtime.version = " + Runtime.version());
    Arrays.stream(SSLContext.getDefault()
        .getSupportedSSLParameters()
        .getNamedGroups())
        .forEach(IO::println);
  }
}
