-- common pre-existing local groups
insert into experimentergroup (id,permissions,version,name,ldap)
        values (ome_nextval('seq_experimentergroup'),-120,0,'OmeroUnitLocal',false);
