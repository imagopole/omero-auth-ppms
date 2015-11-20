-- pre-existing OMERO user, supposed known to PPMS only (not LDAP)
insert into experimenter (id,permissions,version,omename,firstname,lastname,ldap)
        values (ome_nextval('seq_experimenter'),0,0,'foo.doo','Foo','DOO',false);

-- group memberships: local group (OmeroUnitLocal) + active system user
-- user
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,1,3,0,false;
-- OmeroUnitLocal
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,3,3,1,true;

-- local 'foounit' user (should auth against PPMS, not JDBC or LDAP)
insert into password (experimenter_id, hash)
        values (3,null);

