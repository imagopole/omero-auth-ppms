-- pre-existing OMERO user, supposed known to OMERO only (not LDAP nor PPMS)
insert into experimenter (id,permissions,version,omename,firstname,lastname,ldap)
        values (ome_nextval('seq_experimenter'),0,0,'otto_sepp','Otto','SEPP',false);

-- group memberships: local group (OmeroUnitLocal) + active system user
-- user
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,1,2,0,false;
-- OmeroUnitLocal
insert into groupexperimentermap
        (id,permissions,version, parent, child, child_index,owner)
        select ome_nextval('seq_groupexperimentermap'),-52,0,3,2,1,true;

-- local 'dbunit' user
insert into password (experimenter_id, hash)
        values (2,'BFFy/27DsZaHRAXWmNnwlw==');

