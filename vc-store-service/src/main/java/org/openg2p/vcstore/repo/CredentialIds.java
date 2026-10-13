package org.openg2p.vcstore.repo;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CredentialIds {
    // XXXX-XXXX-XXXX over 32 symbols (no I/O/0/1); dashes optional when typed
    private static final Pattern CODE = Pattern.compile("([A-HJ-NP-Z2-9]{4})-?([A-HJ-NP-Z2-9]{4})-?([A-HJ-NP-Z2-9]{4})");

    private CredentialIds() {}

    /**
     * The vault key is the claim code Certify generated (e.g. K7QM-2XPD-9TVR). Accepts what a farmer might
     * type or paste: any case, with or without dashes/spaces, or the full VC id such as
     * 'urn:openg2p:credential:K7QM-2XPD-9TVR'.
     */
    public static String normalize(String raw) {
        if (raw == null) {
            return "";
        }
        String text = raw.trim().toUpperCase(Locale.ROOT).replaceAll("[\\s_]", "");
        int cut = Math.max(text.lastIndexOf(':'), text.lastIndexOf('/'));
        if (cut >= 0) {
            text = text.substring(cut + 1);
        }
        Matcher m = CODE.matcher(text);
        return m.matches() ? m.group(1) + "-" + m.group(2) + "-" + m.group(3) : text;
    }
}
