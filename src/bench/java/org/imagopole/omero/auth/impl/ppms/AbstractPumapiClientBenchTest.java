/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import java.util.Properties;

import org.databene.contiperf.junit.ContiPerfRule;
import org.databene.contiperf.report.CSVSummaryReportModule;
import org.databene.contiperf.report.HtmlReportModule;
import org.imagopole.omero.auth.BenchUtil.TestKeys;
import org.imagopole.ppms.api.PumapiClient;
import org.junit.Before;
import org.junit.Rule;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author seb
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "/pumapi/bench-applicationContext.xml" })
public abstract class AbstractPumapiClientBenchTest {

    /** Application logs */
    protected final Logger log = LoggerFactory.getLogger(AbstractPumapiClientBenchTest.class);

    @Rule
    public ContiPerfRule contiperfRule = new ContiPerfRule(new HtmlReportModule(),
                                                           new CSVSummaryReportModule());

    /** Default client with http remoting. */
    @Autowired
    @Qualifier("defaultPumapiClient")
    protected PumapiClient defaultClient;

    /** Caching provider around the default client. */
    @Autowired
    @Qualifier("cachingPumapiClient")
    protected PumapiClient cachingClient;

    /** Some bench test parameters. */
    @Autowired
    protected Properties benchProperties;

    /** @see TestKeys#LDAP_USERNAME */
    protected String ldapUserName;

    /** @see TestKeys#LOCAL_USERNAME */
    protected String localUsername;

    /** @see TestKeys#UNKNOWN_USERNAME */
    protected String unknownUsername;

    /** @see TestKeys#SYSTEM_ID */
    protected Long systemId;

    /** @see TestKeys#UNKNOWN_SYSTEM_ID */
    protected Long unknownSystemId;

    /** @see TestKeys#GROUP_KEY */
    protected String groupKey;

    /** @see TestKeys#UNKNOWN_GROUP_KEY */
    protected String unknownGroupKey;

    protected String ldapWrongPassword;

    protected String ldapRightPassword;

    protected String localWrongPassword;

    protected String localRightPassword;

    @Before
    public void setUp() {
        // getUser
        ldapUserName = benchProperties.getProperty(TestKeys.LDAP_USERNAME);
        localUsername = benchProperties.getProperty(TestKeys.LOCAL_USERNAME);
        unknownUsername = benchProperties.getProperty(TestKeys.UNKNOWN_USERNAME);

        // getSystem
        String system = benchProperties.getProperty(TestKeys.SYSTEM_ID);
        String unknownSystem = benchProperties.getProperty(TestKeys.UNKNOWN_SYSTEM_ID);
        systemId = (null == system ? null : Long.parseLong(system));
        unknownSystemId = (null == unknownSystem ? null : Long.parseLong(unknownSystem));

        // getGroup
        groupKey = benchProperties.getProperty(TestKeys.GROUP_KEY);
        unknownGroupKey = benchProperties.getProperty(TestKeys.UNKNOWN_GROUP_KEY);

        // authenticate
        ldapRightPassword = benchProperties.getProperty(TestKeys.LDAP_PWD_OK);
        ldapWrongPassword = benchProperties.getProperty(TestKeys.LDAP_PWD_KO);
        localRightPassword = benchProperties.getProperty(TestKeys.LOCAL_PWD_OK);
        localWrongPassword = benchProperties.getProperty(TestKeys.LOCAL_PWD_KO);

        log.debug("ldapUserName: {} - localUsername: {} - unknownUsername: {}",
                 ldapUserName, localUsername, unknownUsername);
        log.debug("systemId: {} - unknownSystemId: {}", systemId, unknownSystemId);
        log.debug("groupKey: {} - unknownGroupKey: {}", groupKey, unknownGroupKey);
    }

}
