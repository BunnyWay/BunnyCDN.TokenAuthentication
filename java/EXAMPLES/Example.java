import BunnyCDN.TokenSigner;

public class Example {

    public static void main(String[] args) {
        String securityKey = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40";
        long expiry = 315569520; // in seconds
        String pathAllowed = "/";

        String signedUrl = TokenSigner.signUrl(
                "https://token-tester.b-cdn.net/300kb.jpg",
                securityKey,
                expiry,
                "",
                false,
                pathAllowed,
                "CA",
                null
        );
        System.out.println(signedUrl);
    }
}
