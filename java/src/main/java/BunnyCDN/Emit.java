package BunnyCDN;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * e2e emitter: reads e2e/inputs.json, signs every case with {@link TokenSigner},
 * extracts the token from each signed URL, and prints a single JSON object
 * mapping case name -> token to stdout.
 *
 * <p>Java has no JSON in its standard library, so this contains a tiny
 * hand-rolled JSON parser sufficient for the flat inputs.json structure
 * (a top-level object with string/number values plus a "cases" array of
 * flat objects).
 *
 * <p>Usage (path to inputs.json may be passed as arg[0]; otherwise it is
 * resolved relative to this file at ../../../../../../e2e/inputs.json, i.e.
 * the repo's e2e/inputs.json):
 * <pre>
 *   javac -d out src/main/java/BunnyCDN/TokenSigner.java src/main/java/BunnyCDN/Emit.java
 *   java -cp out BunnyCDN.Emit ../e2e/inputs.json
 * </pre>
 */
public final class Emit {

    public static void main(String[] args) throws IOException {
        Path inputsPath;
        if (args.length > 0) {
            inputsPath = Paths.get(args[0]);
        } else {
            // Default: repo-root/e2e/inputs.json relative to the working dir (java/).
            inputsPath = Paths.get("..", "e2e", "inputs.json");
        }

        String text = new String(Files.readAllBytes(inputsPath), StandardCharsets.UTF_8);
        Object parsed = new JsonParser(text).parse();
        @SuppressWarnings("unchecked")
        Map<String, Object> root = (Map<String, Object>) parsed;

        String key = (String) root.get("key");
        long expires = ((Number) root.get("expires")).longValue();
        String host = (String) root.get("host");

        @SuppressWarnings("unchecked")
        List<Object> cases = (List<Object>) root.get("cases");

        // Preserve input order in the output object.
        Map<String, String> result = new LinkedHashMap<>();
        for (Object co : cases) {
            @SuppressWarnings("unchecked")
            Map<String, Object> c = (Map<String, Object>) co;

            String name = (String) c.get("name");
            String path = (String) c.get("path");
            String userIp = (String) c.get("userIp");
            boolean isDirectory = (Boolean) c.get("isDirectory");
            String pathAllowed = (String) c.get("pathAllowed");
            String countriesAllowed = (String) c.get("countriesAllowed");
            String countriesBlocked = (String) c.get("countriesBlocked");
            boolean ignoreParams = (Boolean) c.get("ignoreParams");
            int speedLimit = ((Number) c.get("speedLimit")).intValue();
            // countryCode is intentionally ignored for signing.

            String signedUrl = TokenSigner.signUrl(
                    host + path,
                    key,
                    86400L,
                    userIp,
                    isDirectory,
                    pathAllowed,
                    countriesAllowed,
                    countriesBlocked,
                    ignoreParams,
                    Long.valueOf(expires),
                    speedLimit
            );

            result.put(name, extractToken(signedUrl));
        }

        System.out.println(toJson(result));
    }

    /**
     * Extracts the token from a signed URL: substring after "bcdn_token=" if
     * present, else after "token=", up to the next "&" (or end of string).
     */
    static String extractToken(String url) {
        String marker = url.contains("bcdn_token=") ? "bcdn_token=" : "token=";
        int start = url.indexOf(marker) + marker.length();
        int end = url.indexOf('&', start);
        if (end == -1) {
            end = url.length();
        }
        return url.substring(start, end);
    }

    /** Builds a JSON object string {"name":"token",...} with proper escaping. */
    static String toJson(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, String> e : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(quote(e.getKey())).append(':').append(quote(e.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * Minimal recursive-descent JSON parser. Supports objects, arrays,
     * strings (with escapes), numbers (as Long/Double), booleans, and null.
     * Sufficient for the flat e2e inputs.json structure.
     */
    static final class JsonParser {
        private final String s;
        private int pos;

        JsonParser(String s) {
            this.s = s;
        }

        Object parse() {
            skipWs();
            Object value = parseValue();
            skipWs();
            if (pos != s.length()) {
                throw new IllegalStateException("Trailing content at position " + pos);
            }
            return value;
        }

        private Object parseValue() {
            skipWs();
            char c = peek();
            switch (c) {
                case '{': return parseObject();
                case '[': return parseArray();
                case '"': return parseString();
                case 't': case 'f': return parseBoolean();
                case 'n': return parseNull();
                default:  return parseNumber();
            }
        }

        private Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> obj = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') {
                pos++;
                return obj;
            }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                expect(':');
                Object value = parseValue();
                obj.put(key, value);
                skipWs();
                char c = next();
                if (c == '}') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalStateException("Expected ',' or '}' at position " + (pos - 1));
                }
            }
            return obj;
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> arr = new ArrayList<>();
            skipWs();
            if (peek() == ']') {
                pos++;
                return arr;
            }
            while (true) {
                arr.add(parseValue());
                skipWs();
                char c = next();
                if (c == ']') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalStateException("Expected ',' or ']' at position " + (pos - 1));
                }
            }
            return arr;
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char esc = next();
                    switch (esc) {
                        case '"':  sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/'); break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        case 'u':
                            String hex = s.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                            break;
                        default:
                            throw new IllegalStateException("Invalid escape: \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Boolean parseBoolean() {
            if (s.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalStateException("Invalid boolean at position " + pos);
        }

        private Object parseNull() {
            if (s.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalStateException("Invalid null at position " + pos);
        }

        private Number parseNumber() {
            int start = pos;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '-' || c == '+'
                        || c == '.' || c == 'e' || c == 'E') {
                    pos++;
                } else {
                    break;
                }
            }
            String num = s.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E")) {
                return Double.valueOf(num);
            }
            return Long.valueOf(num);
        }

        private void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private char peek() {
            if (pos >= s.length()) {
                throw new IllegalStateException("Unexpected end of input");
            }
            return s.charAt(pos);
        }

        private char next() {
            if (pos >= s.length()) {
                throw new IllegalStateException("Unexpected end of input");
            }
            return s.charAt(pos++);
        }

        private void expect(char c) {
            char actual = next();
            if (actual != c) {
                throw new IllegalStateException(
                        "Expected '" + c + "' but got '" + actual + "' at position " + (pos - 1));
            }
        }
    }

    private Emit() {
    }
}
