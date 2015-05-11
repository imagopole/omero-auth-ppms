---
-- Template for benchmark tests database seeding
-- Values must be kept in sync with settings from BENCH_CONFIG/bench.config.location
---

-- pre-existing OMERO user, supposed known to both LDAP and PPMS
insert into experimenter (id,permissions,version,omename,firstname,lastname,ldap)
        values (ome_nextval('seq_experimenter'),0,0,'${bench.ppms.ldap_user}','Bench-User','PPMS-LDAP',true);

-- LDAP enabled user: no password entry required
--insert into password (experimenter_id, hash)
--        values (currval('seq_experimenter'),null);
