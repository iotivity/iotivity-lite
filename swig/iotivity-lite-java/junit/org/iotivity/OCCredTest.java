package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;

public class OCCredTest {
    @Test
    public void testReadCredusage()
    {
        assertEquals("oic.sec.cred.trustca", OCCredUtil.readCredUsage(OCCredUsage.OC_CREDUSAGE_TRUSTCA));
        assertEquals("oic.sec.cred.cert", OCCredUtil.readCredUsage(OCCredUsage.OC_CREDUSAGE_IDENTITY_CERT));
        assertEquals("oic.sec.cred.rolecert", OCCredUtil.readCredUsage(OCCredUsage.OC_CREDUSAGE_ROLE_CERT));
        assertEquals("oic.sec.cred.mfgtrustca", OCCredUtil.readCredUsage(OCCredUsage.OC_CREDUSAGE_MFG_TRUSTCA));
        assertEquals("oic.sec.cred.mfgcert", OCCredUtil.readCredUsage(OCCredUsage.OC_CREDUSAGE_MFG_CERT));
        assertEquals("None", OCCredUtil.readCredUsage(OCCredUsage.OC_CREDUSAGE_NULL));
    }

    @Test
    public void testReadEncoding()
    {
        assertEquals("oic.sec.encoding.base64", OCCredUtil.readEncoding(OCEncoding.OC_ENCODING_BASE64));
        assertEquals("oic.sec.encoding.raw", OCCredUtil.readEncoding(OCEncoding.OC_ENCODING_RAW));
        assertEquals("oic.sec.encoding.pem", OCCredUtil.readEncoding(OCEncoding.OC_ENCODING_PEM));
        assertEquals("oic.sec.encoding.handle", OCCredUtil.readEncoding(OCEncoding.OC_ENCODING_HANDLE));
        assertEquals("Unknown", OCCredUtil.readEncoding(OCEncoding.OC_ENCODING_UNSUPPORTED));
    }

    @Test
    public void testParseCredUsage()
    {
        assertEquals(OCCredUsage.OC_CREDUSAGE_TRUSTCA , OCCredUtil.parseCredUsage("oic.sec.cred.trustca"));
        assertEquals(OCCredUsage.OC_CREDUSAGE_IDENTITY_CERT , OCCredUtil.parseCredUsage("oic.sec.cred.cert"));
        assertEquals(OCCredUsage.OC_CREDUSAGE_ROLE_CERT , OCCredUtil.parseCredUsage("oic.sec.cred.rolecert"));
        assertEquals(OCCredUsage.OC_CREDUSAGE_MFG_TRUSTCA , OCCredUtil.parseCredUsage("oic.sec.cred.mfgtrustca"));
        assertEquals(OCCredUsage.OC_CREDUSAGE_MFG_CERT , OCCredUtil.parseCredUsage("oic.sec.cred.mfgcert"));
        assertEquals(OCCredUsage.OC_CREDUSAGE_NULL , OCCredUtil.parseCredUsage("oic.sec.cred.notreal"));
    }

    @Test
    public void testParseEncoding()
    {
        assertEquals(OCEncoding.OC_ENCODING_BASE64, OCCredUtil.parseEncoding("oic.sec.encoding.base64"));
        assertEquals(OCEncoding.OC_ENCODING_RAW, OCCredUtil.parseEncoding("oic.sec.encoding.raw"));
        assertEquals(OCEncoding.OC_ENCODING_HANDLE, OCCredUtil.parseEncoding("oic.sec.encoding.handle"));
        assertEquals(OCEncoding.OC_ENCODING_PEM, OCCredUtil.parseEncoding("oic.sec.encoding.pem"));
        assertEquals(OCEncoding.OC_ENCODING_UNSUPPORTED, OCCredUtil.parseEncoding("oic.sec.encoding.not.real"));
    }

    @Test
    public void testCredTypeString()
    {
        assertEquals("Symmetric pair-wise key", OCCredUtil.credTypeString(OCCredType.OC_CREDTYPE_PSK));
        assertEquals("Asymmetric signing key with certificate", OCCredUtil.credTypeString(OCCredType.OC_CREDTYPE_CERT));
        assertEquals("Unknown", OCCredUtil.credTypeString(OCCredType.OC_CREDTYPE_NULL));
    }
}
