package org.openg2p.esignet.vcstore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MiniJsonTest {

    @Test
    void parsesTheRealVcStoreReplies() {
        Map<String, Object> send = MiniJson.parseObject(
                "{\"channel\":\"EMAIL\",\"destinationMasked\":\"r***@example.com\",\"expiresInSeconds\":300,\"resendAfterSeconds\":30}");
        assertEquals("EMAIL", send.get("channel"));
        assertEquals("r***@example.com", send.get("destinationMasked"));
        assertEquals(300L, send.get("expiresInSeconds"));

        Map<String, Object> verify = MiniJson.parseObject("{\"valid\":true,\"psut\":\"K7QM-2XPD-9TVR\"}");
        assertEquals(Boolean.TRUE, verify.get("valid"));
        assertEquals("K7QM-2XPD-9TVR", verify.get("psut"));

        Map<String, Object> error = MiniJson.parseObject("{\"error\":\"invalid_credential_id\",\"error_description\":\"Unknown credential id\"}");
        assertEquals("invalid_credential_id", error.get("error"));
    }

    @Test
    void parsesNestedValuesNumbersAndWhitespace() {
        Map<String, Object> m = MiniJson.parseObject(" { \"a\" : [1, 2.5, \"x\", null, true, {\"b\": false}] , \"n\": -12, \"e\": 1e3 } ");
        List<?> a = (List<?>) m.get("a");
        assertEquals(6, a.size());
        assertEquals(1L, a.get(0));
        assertEquals(2.5, a.get(1));
        assertNull(a.get(3));
        assertEquals(Boolean.FALSE, ((Map<?, ?>) a.get(5)).get("b"));
        assertEquals(-12L, m.get("n"));
        assertEquals(1000.0, m.get("e"));
        assertTrue(MiniJson.parseObject("{}").isEmpty());
    }

    @Test
    void handlesEscapesAndUnicode() {
        Map<String, Object> m = MiniJson.parseObject("{\"s\":\"a\\\"b\\\\c\\n\\t\\/\\u00fc\\u0001\"}");
        assertEquals("a\"b\\c\n\t/\u00fc\u0001", m.get("s"));
    }

    @Test
    void buildsEscapedJsonThatParsesBack() {
        String nasty = "a\"b\\c\n\r\t\b\f\u0001 \u00fc \uD83D\uDE00 } { , :";
        String json = MiniJson.object("credentialId", "K7QM-2XPD-9TVR", "otp", nasty, "none", null);
        Map<String, Object> back = MiniJson.parseObject(json);
        assertEquals("K7QM-2XPD-9TVR", back.get("credentialId"));
        assertEquals(nasty, back.get("otp"));
        assertTrue(back.containsKey("none") && back.get("none") == null);
    }

    @Test
    void rejectsMalformedInput() {
        for (String bad : new String[] {"", "   ", "not json", "{", "{\"a\"}", "{\"a\":}", "[1,2]", "\"str\"", "{\"a\":1} extra",
                "{\"a\":\"unterminated}", "{\"a\":\"\\q\"}", "{\"a\":\"\\u12\"}", "{\"a\":1,}", "{'a':1}"}) {
            assertThrows(IllegalArgumentException.class, () -> MiniJson.parseObject(bad), "should reject: " + bad);
        }
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parseObject(null));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.object("odd"));
    }
}
