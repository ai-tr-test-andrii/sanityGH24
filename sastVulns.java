import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class AdditionalSastCases {

    // 1. SQL Injection (High)
    public void findUser(HttpServletRequest request) throws Exception {

        String username = request.getParameter("username");

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test",
                "user",
                "pass");

        Statement stmt = conn.createStatement();

        stmt.executeQuery(
                "SELECT * FROM users WHERE username='" + username + "'");
    }

    // 2. Path Traversal (High)
    public File getFile(HttpServletRequest request) {

        String file = request.getParameter("file");

        return new File("/opt/app/data/" + file);
    }

    // 3. XPath Injection (High)
    public String createXPath(HttpServletRequest request) {

        String id = request.getParameter("id");

        return "//users/user[@id='" + id + "']";
    }

    // 4. XML External Entity (XXE) (High)
    public void parseXml(HttpServletRequest request) throws Exception {

        String xml = request.getParameter("xml");

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Disable DTD and external entity processing to prevent XXE attacks (CWE-611)
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();

        builder.parse(new ByteArrayInputStream(xml.getBytes()));
    }

    // 5. Open Redirect (Medium)
    public String redirect(HttpServletRequest request) {

        String target = request.getParameter("url");

        return "redirect:" + target;
    }

    // 6. Information Exposure (Low)
    public void printStackTrace(Exception e) {

        e.printStackTrace();
    }

    // 7. Hardcoded Password (High)
    public void connect() throws Exception {

        DriverManager.getConnection(
                "jdbc:mysql://localhost/test",
                "admin",
                "SuperSecretPassword123");
    }
}