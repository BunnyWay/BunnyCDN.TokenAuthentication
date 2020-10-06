public class Main {

	public static void main(String args[]) {

		TokenSigner signerObject = new TokenSigner();
		String securityKey = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40";
		String expiry = "315569520"; // in seconds
		String pathAllowed = "/";

		try {
			System.out.println(signerObject.signUrl("https://token-tester.b-cdn.net/300kb.jpg", securityKey, expiry,
					null, false, pathAllowed, "CA", null));
		} catch (Exception e) {
			System.out.println("Failed to sign");
		}

	}

}
