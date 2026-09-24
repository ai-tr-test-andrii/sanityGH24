import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for AdditionalSastCases – verifies that the SQL injection vulnerability
 * in {@code findUser} has been remediated by replacing string-concatenated SQL
 * with a parameterized {@link PreparedStatement}.
 *
 * <p>Security regression tests:
 * <ul>
 *   <li>The SQL template must contain a {@code ?} placeholder, never a literal value.</li>
 *   <li>The username is bound via {@link PreparedStatement#setString}, never concatenated.</li>
 *   <li>A classic SQL-injection payload (single-quote bypass) must not alter the query template.</li>
 * </ul>
 */
class AdditionalSastCasesTest {

    private AdditionalSastCases sut;
    private HttpServletRequest request;
    private Connection           connection;
    private PreparedStatement    preparedStatement;

    @BeforeEach
    void setUp() throws Exception {
        sut               = new AdditionalSastCases();
        request           = mock(HttpServletRequest.class);
        connection        = mock(Connection.class);
        preparedStatement = mock(PreparedStatement.class);

        when(preparedStatement.executeQuery()).thenReturn(mock(ResultSet.class));
    }

    // -----------------------------------------------------------------------
    // Helper: invoke findUser while the DriverManager is stubbed to return
    // our mock Connection.
    // -----------------------------------------------------------------------
    private void invokeFindUser(String usernameValue) throws Exception {
        when(request.getParameter("username")).thenReturn(usernameValue);
        try (MockedStatic<DriverManager> dm = mockStatic(DriverManager.class)) {
            dm.when(() -> DriverManager.getConnection(anyString(), anyString(), anyString()))
              .thenReturn(connection);
            when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
            sut.findUser(request);
        }
    }

    // -----------------------------------------------------------------------
    // 1. Functional correctness – normal username flows through without error
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("findUser completes successfully for a valid username")
    void findUser_normalUsername_executesWithoutException() throws Exception {
        assertDoesNotThrow(() -> invokeFindUser("alice"));
    }

    // -----------------------------------------------------------------------
    // 2. Parameterized query used – SQL template must contain '?' placeholder
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("findUser calls prepareStatement with a parameterized query (contains '?')")
    void findUser_usesParameterizedQuery_queryContainsPlaceholder() throws Exception {
        invokeFindUser("bob");

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        verify(connection).prepareStatement(sqlCaptor.capture());

        String sql = sqlCaptor.getValue();
        assertTrue(sql.contains("?"),
                "SQL template must use a '?' placeholder, not string concatenation. Got: " + sql);
    }

    // -----------------------------------------------------------------------
    // 3. Username bound via setString – never concatenated into the query text
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("findUser binds username via PreparedStatement.setString, not concatenation")
    void findUser_usernameIsBoundAsParameter_notConcatenated() throws Exception {
        String username = "charlie";
        invokeFindUser(username);

        // setString(1, username) must have been called exactly once
        verify(preparedStatement).setString(1, username);
    }

    // -----------------------------------------------------------------------
    // 4. SQL-injection payload must NOT appear in the query template
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("SQL-injection payload does not alter the prepared SQL template")
    void findUser_sqlInjectionPayload_doesNotModifyQueryTemplate() throws Exception {
        // Classic tautology-based injection attempt
        String maliciousUsername = "' OR '1'='1";
        invokeFindUser(maliciousUsername);

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        verify(connection).prepareStatement(sqlCaptor.capture());

        String sql = sqlCaptor.getValue();
        // The raw injection string must NOT appear in the query template
        assertFalse(sql.contains(maliciousUsername),
                "Injection payload must not be embedded in the SQL template. Got: " + sql);
        // The template must still be parameterized
        assertTrue(sql.contains("?"),
                "SQL template must retain its '?' placeholder. Got: " + sql);
        // The payload is bound as a parameter value, not in the template
        verify(preparedStatement).setString(1, maliciousUsername);
    }

    // -----------------------------------------------------------------------
    // 5. UNION-based injection payload is similarly contained as a parameter
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("UNION-based injection payload is bound as a parameter, not injected")
    void findUser_unionInjectionPayload_boundAsParameter() throws Exception {
        String unionPayload = "' UNION SELECT password FROM admin--";
        invokeFindUser(unionPayload);

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        verify(connection).prepareStatement(sqlCaptor.capture());

        String sql = sqlCaptor.getValue();
        assertFalse(sql.contains("UNION"),
                "UNION keyword must not appear in the SQL template. Got: " + sql);
        verify(preparedStatement).setString(1, unionPayload);
    }

    // -----------------------------------------------------------------------
    // 6. executeQuery is called on the PreparedStatement (no-arg form)
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("findUser calls PreparedStatement.executeQuery() with no arguments")
    void findUser_callsExecuteQueryOnPreparedStatement() throws Exception {
        invokeFindUser("diana");

        // No-arg executeQuery() – not the string-argument variant on Statement
        verify(preparedStatement).executeQuery();
        // The String-argument overload that would accept a raw SQL string must NOT be called
        verify(preparedStatement, never()).executeQuery(anyString());
    }

    // -----------------------------------------------------------------------
    // 7. Null username is handled as a bound null parameter (no NPE / injection)
    // -----------------------------------------------------------------------
    @Test
    @DisplayName("Null username is safely bound as a null parameter without exception")
    void findUser_nullUsername_doesNotThrow() throws Exception {
        assertDoesNotThrow(() -> invokeFindUser(null));
        // setString still called (with null) – the database handles it safely
        verify(preparedStatement).setString(eq(1), isNull());
    }
}
