package dev.logicojp.example.pqchybridtls.jfr;

import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.lang.reflect.Method;
import java.util.Map;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

final class NegotiatedNamedGroupCaptureSupport {

    static final String SESSION_VALUE_KEY =
            NegotiatedNamedGroupCaptureSupport.class.getName() + ".negotiatedNamedGroup";
    static final String ADD_OPENS_HINT =
            "unavailable (add --add-opens java.base/sun.security.ssl=ALL-UNNAMED)";

    private NegotiatedNamedGroupCaptureSupport() {
    }

    static String getCapturedNegotiatedNamedGroup(SSLSession session) {
        if (session == null) {
            return null;
        }
        Object value = session.getValue(SESSION_VALUE_KEY);
        if (!(value instanceof String text) || text.isBlank()) {
            return null;
        }
        return text;
    }

    static void captureFromEngine(SSLEngine engine) {
        SSLSession fallbackSession = engine.getSession();

        try {
            Object connectionContext = readField(engine, "conContext");
            SSLSession connectionSession = resolveConnectionSession(connectionContext, fallbackSession);
            if (connectionSession == null) {
                return;
            }

            if (!isUnavailable(getCapturedNegotiatedNamedGroup(connectionSession))) {
                return;
            }

            Object handshakeContext = readField(connectionContext, "handshakeContext");
            if (handshakeContext == null) {
                return;
            }

            String negotiatedNamedGroup = extractNegotiatedNamedGroup(handshakeContext);
            if (negotiatedNamedGroup == null || negotiatedNamedGroup.isBlank()) {
                return;
            }

            storeCapturedNegotiatedNamedGroup(connectionSession, negotiatedNamedGroup);
        } catch (InaccessibleObjectException exception) {
            storeUnavailableIfAbsent(fallbackSession, ADD_OPENS_HINT);
        } catch (ReflectiveOperationException exception) {
            storeUnavailableIfAbsent(
                    fallbackSession,
                    "unavailable (" + exception.getClass().getSimpleName() + ")"
            );
        }
    }

    private static SSLSession resolveConnectionSession(Object connectionContext, SSLSession fallbackSession)
            throws ReflectiveOperationException {
        Object sessionObject = readField(connectionContext, "conSession");
        if (sessionObject instanceof SSLSession session) {
            return session;
        }
        return fallbackSession;
    }

    private static void storeCapturedNegotiatedNamedGroup(SSLSession session, String value) {
        if (session == null || value == null || value.isBlank()) {
            return;
        }
        session.putValue(SESSION_VALUE_KEY, value);
    }

    private static void storeUnavailableIfAbsent(SSLSession session, String value) {
        if (session == null || value == null || value.isBlank()) {
            return;
        }
        String current = getCapturedNegotiatedNamedGroup(session);
        if (current == null || current.isBlank()) {
            session.putValue(SESSION_VALUE_KEY, value);
        }
    }

    static boolean isUnavailable(String value) {
        return value == null || value.isBlank() || value.startsWith("unavailable");
    }

    private static String extractNegotiatedNamedGroup(Object handshakeContext) throws ReflectiveOperationException {
        String extensionDerived = extractNamedGroupFromHandshakeExtensions(handshakeContext);
        if (extensionDerived != null && !extensionDerived.isBlank()) {
            return extensionDerived;
        }

        Object selectedNamedGroup = readField(handshakeContext, "serverSelectedNamedGroup");
        if (selectedNamedGroup != null) {
            return selectedNamedGroup.toString();
        }

        return null;
    }

    private static String extractNamedGroupFromHandshakeExtensions(Object handshakeContext)
            throws ReflectiveOperationException {
        Object extensionsObject = readField(handshakeContext, "handshakeExtensions");
        if (!(extensionsObject instanceof Map<?, ?> extensions)) {
            return null;
        }

        for (Object extensionSpec : extensions.values()) {
            if (extensionSpec == null) {
                continue;
            }
            String simpleName = extensionSpec.getClass().getSimpleName();
            if ("SHKeyShareSpec".equals(simpleName)) {
                Object serverShare = readField(extensionSpec, "serverShare");
                int namedGroupId = ((Number) readField(serverShare, "namedGroupId")).intValue();
                return namedGroupName(namedGroupId);
            }
            if ("HRRKeyShareSpec".equals(simpleName)) {
                int namedGroupId = ((Number) readField(extensionSpec, "selectedGroup")).intValue();
                return namedGroupName(namedGroupId);
            }
        }

        return null;
    }

    private static String namedGroupName(int namedGroupId) throws ReflectiveOperationException {
        String knownGroup = knownNamedGroupName(namedGroupId);
        if (knownGroup != null) {
            return knownGroup;
        }

        Class<?> namedGroupClass = Class.forName("sun.security.ssl.NamedGroup");
        Method nameOf = namedGroupClass.getDeclaredMethod("nameOf", int.class);
        nameOf.setAccessible(true);
        Object groupName = nameOf.invoke(null, namedGroupId);
        return groupName != null ? groupName.toString() : "UNDEFINED-NAMED-GROUP(" + namedGroupId + ")";
    }

    private static String knownNamedGroupName(int namedGroupId) {
        return switch (namedGroupId) {
            case 0x0017 -> "secp256r1";
            case 0x0018 -> "secp384r1";
            case 0x0019 -> "secp521r1";
            case 0x001D -> "x25519";
            case 0x001E -> "x448";
            case 0x0100 -> "ffdhe2048";
            case 0x0101 -> "ffdhe3072";
            case 0x0102 -> "ffdhe4096";
            case 0x0103 -> "ffdhe6144";
            case 0x0104 -> "ffdhe8192";
            case 0x11EC -> "X25519MLKEM768";
            default -> null;
        };
    }

    private static Object readField(Object target, String fieldName) throws ReflectiveOperationException {
        Field field = findField(target.getClass(), fieldName);
        field.setAccessible(true);
        return field.get(target);
    }

    private static Field findField(Class<?> type, String fieldName) throws NoSuchFieldException {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(fieldName);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }
}
