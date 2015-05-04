-- pre-existing OMERO user, supposed known to both LDAP and PPMS
insert into experimenter (id,permissions,version,omename,firstname,lastname)
        values (ome_nextval('seq_experimenter'),0,0,'jbloggs','Joe','BLOGGS');

-- extra pre-existing local groups
insert into experimentergroup (id,permissions,version,name)
        values (ome_nextval('seq_experimentergroup'),-120,0,'OmeroUnitPpmsDuplicate');

-- group memberships: local groups (OmeroUnitLocal + OmeroUnitPpmsDuplicate) + active system user
-- user
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,1,4,0,false;
-- OmeroUnitLocal
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,3,4,1,false;
-- OmeroUnitPpmsDuplicate
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,4,4,2,false;

-- LDAP enabled user
insert into password (experimenter_id, hash, dn)
        values (4,null,'uid=jbloggs,ou=People,dc=example,dc=com');

