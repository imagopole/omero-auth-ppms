package org.imagopole.omero.auth;

import static org.testng.Assert.fail;

import java.io.InputStream;
import java.text.MessageFormat;
import java.util.Properties;

import com.googlecode.flyway.core.Flyway;
import com.googlecode.flyway.core.api.FlywayException;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;

import ome.security.SecuritySystem;
import ome.security.basic.CurrentDetails;
import ome.security.basic.PrincipalHolder;
import ome.server.itests.LoginInterceptor;
import ome.services.sessions.SessionManager;
import ome.services.util.Executor;
import ome.system.OmeroContext;
import ome.system.Principal;
import ome.system.Roles;
import ome.system.ServiceFactory;
import ome.testing.InterceptingServiceFactory;

import org.imagopole.omero.auth.TestsUtil.Env;
import org.imagopole.omero.auth.TestsUtil.LdapUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.interceptor.JamonPerformanceMonitorInterceptor;
import org.testng.annotations.AfterClass;

/**
 * Extended integration test with OMERO.server + in-memory LDAP server + database state reloading.
 *
 * @author seb
 *
 */
public abstract class AbstractOmeroIntegrationTest extends AbstractOmeroServerTest {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(AbstractOmeroIntegrationTest.class);

    /** Database migrations manager. */
    private Flyway flyway = new Flyway();

    /** LDAP fixtures server. */
    private InMemoryDirectoryServer ldapServer;

    /** Factory which provides "wrapped" managed services which handles login as would take place via ISession */
    private ServiceFactory serviceFactory;
    private SecuritySystem securitySystem;
    private PrincipalHolder principalHolder;
    private SessionManager sessionManager;
    private LoginInterceptor loginInterceptor;
    private Executor executor;
    private Roles roles;

    @Override
    protected void setUpBeforeServerStartup(Properties systemProps) {
        try {
            configureLdapServer(systemProps);
        } catch (LDAPException e) {
           log.error("Failed to configure in-memory LDAP server", e);
           fail(e.getMessage());
        } catch (LDIFException e) {
            log.error("Failed to configure in-memory LDAP server", e);
            fail(e.getMessage());
        }

        try {
            configureDatabase(systemProps);
        } catch (FlywayException e) {
           log.error("Failed to configure database", e);
           fail(e.getMessage());
        }
    }

    @Override
    protected void setUpAfterServerStartup(OmeroContext omeroContext) {
        //-- OMERO server boilerplate
        executor = (Executor) omeroContext.getBean("executor");
        principalHolder = (PrincipalHolder) omeroContext.getBean("principalHolder");
        sessionManager = (SessionManager) omeroContext.getBean("sessionManager");
        securitySystem = (SecuritySystem) omeroContext.getBean("securitySystem");

        roles = securitySystem.getSecurityRoles();
        loginInterceptor = new LoginInterceptor((CurrentDetails) principalHolder);

        serviceFactory = new InterceptingServiceFactory(
                        new ServiceFactory(omeroContext),
                        loginInterceptor,
                        new JamonPerformanceMonitorInterceptor());
    }

    private void configureDatabase(Properties systemProps) throws FlywayException {
        String dbName = systemProps.getProperty(Env.OMERO_DB_NAME);
        String dbUser = systemProps.getProperty(Env.OMERO_DB_USER);
        String dbPwd = systemProps.getProperty(Env.OMERO_DB_PASS);

        String jdbcBaseUrl =
            systemProps.getProperty(Env.FLYWAY_DB_BASE_URL, "please-define-a-jdbc-base-url");
        String initDbOnMigrateParam =
            systemProps.getProperty(Env.FLYWAY_DB_INIT_ON_MIGRATE, "false");
        String cleanDbOnMigrateParam =
            systemProps.getProperty(Env.FLYWAY_DB_CLEAN_ON_MIGRATE, "false");

        String jdbcUrl = MessageFormat.format(jdbcBaseUrl, dbName);
        boolean shouldInitDbOnMigrate = Boolean.valueOf(initDbOnMigrateParam);
        boolean shouldCleanDbOnMigrate = Boolean.valueOf(cleanDbOnMigrateParam);

        log.debug("Preparing to reload test database: {} [init:{} - clean:{}]",
                  dbName, shouldInitDbOnMigrate, shouldCleanDbOnMigrate);

        flyway.setDataSource(jdbcUrl, dbUser, dbPwd);
        flyway.setInitOnMigrate(shouldInitDbOnMigrate);
        flyway.setLocations(Env.FLYWAY_DEFAULT_LOCATIONS);

        if (shouldCleanDbOnMigrate) {
            flyway.clean();
        }

        flyway.migrate();
    }

    private void configureLdapServer(Properties systemProps) throws LDAPException, LDIFException {
        log.debug("Preparing to load in-memory LDAP server from: {}", LdapUnit.COMMON_LDIF_LOCATION);

        InMemoryListenerConfig listenerConfig =
            InMemoryListenerConfig.createLDAPConfig(getClass().getSimpleName(), LdapUnit.LISTEN_PORT);

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LdapUnit.BASE_DN);
        config.setListenerConfigs(listenerConfig);

        InputStream is = getClass().getClassLoader().getResourceAsStream(LdapUnit.COMMON_LDIF_LOCATION);
        if (null == is) {
            fail(String.format("Unable to locate base LDIF from %s", LdapUnit.COMMON_LDIF_LOCATION));
        }

        ldapServer = new InMemoryDirectoryServer(config);

        LDIFReader ldifReader = new LDIFReader(is);
        int ldapEntriesCount = ldapServer.importFromLDIF(false, ldifReader);

        if (ldapEntriesCount < LdapUnit.COMMON_LDIF_MIN_ENTRIES) {
            fail(String.format("Unable to load base LDIF entries - expected: %d - actual: %d",
                               LdapUnit.COMMON_LDIF_MIN_ENTRIES, ldapEntriesCount));
        }

        ldapServer.startListening();
        log.debug("Started in-memory LDAP server with: {} entries for listen port: {}",
                  ldapEntriesCount, ldapServer.getListenPort());
    }

    @AfterClass
    public void tearDown() {
        // release potentially lingering sessions
        if (principalHolder.size() > 0) {
            principalHolder.logout();
        }
        sessionManager.closeAll();

        // shut down OMERO
        super.tearDown();

        // shut down LDAP
        if (null != ldapServer) {
            log.debug("Stopping in-memory LDAP server: {}", ldapServer);
            ldapServer.shutDown(true);
        }
    }

    protected Principal getLoginPrincipal() {
        return loginInterceptor.p;
    }

    protected void setLoginPrincipal(Principal principal) {
        loginInterceptor.p = principal;
    }

    /**
     * Returns serviceFactory.
     * @return the serviceFactory
     */
    protected ServiceFactory getServiceFactory() {
        return serviceFactory;
    }

    /**
     * Returns sessionManager.
     * @return the sessionManager
     */
    protected SessionManager getSessionManager() {
        return sessionManager;
    }

    /**
     * Returns executor.
     * @return the executor
     */
    protected Executor getExecutor() {
        return executor;
    }

    /**
     * Returns roles.
     * @return the roles
     */
    protected Roles getRoles() {
        return roles;
    }

}
