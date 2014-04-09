/**
 *
 */
package org.imagopole.omero.auth.impl.ppms;

import java.util.List;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import ome.tools.spring.ShutdownSafeEhcacheManagerFactoryBean;

import org.imagopole.ppms.api.PumapiClient;
import org.imagopole.ppms.api.PumapiException;
import org.imagopole.ppms.api.config.PumapiConfig;
import org.imagopole.ppms.api.dto.PpmsGroup;
import org.imagopole.ppms.api.dto.PpmsSystem;
import org.imagopole.ppms.api.dto.PpmsUser;
import org.imagopole.ppms.api.dto.PpmsUserPrivilege;
import org.imagopole.ppms.util.Check;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A caching wrapper around a {@link PumapiClient}'s implementation.
 *
 * Only a subset of remote invocations are intercepted by the cache - volatile or uncacheable
 * data is passed through the underlying client delegate.
 *
 * @author seb
 *
 * @see http://ehcache.org/documentation/get-started/getting-started#cache-aside
 * @see ShutdownSafeEhcacheManagerFactoryBean
 */
public class CachingPumapiClient implements PumapiClient {

    /** Application logs */
    private final Logger log = LoggerFactory.getLogger(CachingPumapiClient.class);

    /** "Actual" PPMS client delegate. */
    private PumapiClient delegate;

    /** Injected {@link CacheManager} used to create various caches. */
    private CacheManager cacheManager;

    protected CachingPumapiClient() {
        super();
    }

    public CachingPumapiClient(PumapiClient delegate, CacheManager cacheManager) {
        super();

        Check.notNull(delegate, "delegate");
        Check.notNull(cacheManager, "cacheManager");
        this.delegate = delegate;
        this.cacheManager = cacheManager;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PumapiConfig getConfig() {
        return delegate.getConfig();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setConfig(PumapiConfig config) {
        delegate.setConfig(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getUsers(Boolean active) throws PumapiException {
        // no caching - not used within the auth extension
        return delegate.getUsers(active);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PpmsUser getUser(String login) throws PumapiException {
        Check.notEmpty(login, "login");

        PpmsUser result = null;

        final String key = buildKey(CacheConfig.GET_USER_KEY, login);
        final Element element = readFromCache(key);

        if (null == element) {

            result = delegate.getUser(login);
            writeToCache(key, result);

        } else {

            result = (PpmsUser) element.getObjectValue();

        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PpmsUserPrivilege> getUserRights(String login) throws PumapiException {
        // no caching - volatile data
        return delegate.getUserRights(login);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PpmsGroup getGroup(String unitLogin) throws PumapiException {
        Check.notEmpty(unitLogin, "unitLogin");

        PpmsGroup result = null;

        final String key = buildKey(CacheConfig.GET_GROUP_KEY, unitLogin);
        final Element element = readFromCache(key);

        if (null == element) {

            result = delegate.getGroup(unitLogin);
            writeToCache(key, result);

        } else {

            result = (PpmsGroup) element.getObjectValue();

        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PpmsSystem getSystem(Long systemId) throws PumapiException {
        Check.notNull(systemId, "systemId");

        PpmsSystem result = null;

        final String key = buildKey(CacheConfig.GET_SYSTEM_KEY, systemId);
        final Element element = readFromCache(key);

        if (null == element) {

            result = delegate.getSystem(systemId);
            writeToCache(key, result);

        } else {

            result = (PpmsSystem) element.getObjectValue();

        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean authenticate(String login, String password) throws PumapiException {
        // no caching - authentication data!
        return delegate.authenticate(login, password);
    }

    private final Element readFromCache(String key) throws IllegalStateException, CacheException {
        Ehcache cache = getCacheOrFail();
        Element result = cache.get(key);
        boolean isEmpty = (null == result);

        log.debug("[external_auth][ppms][cache] Loading cache for key: {} [empty:{}]", key, isEmpty);
        return result;
    }

    private final void writeToCache(String key, Object value) {
        log.debug("[external_auth][ppms][cache] Writing to cache for key: {}", key);
        Ehcache cache = getCacheOrFail();
        Element element = new Element(key, value);
        cache.put(element);
    }

    private final Ehcache getCacheOrFail() {
        Ehcache cache = cacheManager.getEhcache(CacheConfig.CACHE_NAME);
        Check.notNull(cache, "cache");

        return cache;
    }

    private final String buildKey(String keyFormat, Object... args) {
        return String.format(keyFormat, args);
    }

    /**
     * Internal settings for cache and keys creation/lookup.
     *
     * @author seb
     *
     */
    private final class CacheConfig {
        /** Main cache name. */
        private final static String CACHE_NAME     = "pumapiClientCache";

        /** Key format for {@link PumapiClient#getUser(String)} calls. */
        private final static String GET_USER_KEY   = "getUser-%s";

        /** Key format for {@link PumapiClient#getGroup(String)} calls. */
        private final static String GET_GROUP_KEY  = "getGroup-%s";

        /** Key format for {@link PumapiClient#getSystem(Long)} calls. */
        private final static String GET_SYSTEM_KEY = "getSystem-%d";

        /** Constants class. */
        private CacheConfig() {
            super();
        }
    }

}
